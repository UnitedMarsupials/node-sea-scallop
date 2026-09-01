from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, StrEnum
from pathlib import Path
from typing import Dict, Iterator, Tuple

import lief
from rich import print

from scallop.stomp import invalidate_code_cache


NODE_SEA_MAGIC = bytes.fromhex("20da4301")
NODE_SEA_MAGIC_VALUE = int.from_bytes(NODE_SEA_MAGIC, byteorder="little")


class SeaBinaryType(StrEnum):
    PE = "PE"
    ELF = "ELF"
    MACHO = "MACHO_MAN_RANDY_SAVAGE"


class SeaBlobLayout(StrEnum):
    LEGACY = "legacy"
    EXEC_ARGV = "exec_argv"
    MAIN_CODE_FORMAT = "main_code_format"


class SeaBlobFlags(IntFlag):
    DEFAULT = 0
    DISABLE_EXPERIMENTAL_SEA_WARNING = 1 << 0
    USE_SNAPSHOT = 1 << 1
    USE_CODE_CACHE = 1 << 2
    INCLUDE_ASSETS = 1 << 3
    INCLUDE_EXEC_ARGV = 1 << 4


class SeaExecArgvExtension(IntEnum):
    NONE = 0
    ENV = 1
    CLI = 2


class SeaMainCodeFormat(IntEnum):
    COMMONJS = 0
    MODULE = 1


@dataclass
class SeaBlob:
    magic: int
    flags: SeaBlobFlags
    machine_width: int
    code_path: str
    sea_resource: bytes  # Either a source file or a snapshot blob
    code_cache: bytes | None
    assets: Dict[str, bytes] | None = None
    layout: SeaBlobLayout = SeaBlobLayout.LEGACY
    exec_argv_extension: SeaExecArgvExtension | None = None
    main_code_format: SeaMainCodeFormat | None = None
    exec_argv: list[str] = field(default_factory=list)
    blob_raw: bytes | None = None


class _BlobReader:
    def __init__(self, data: bytes, machine_width: int):
        if machine_width not in (4, 8):
            raise ValueError(f"Unsupported machine width: {machine_width}")
        self.data = data
        self.machine_width = machine_width
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read_uint(self, size: int, field_name: str) -> int:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError(f"Truncated SEA blob while reading {field_name}")
        value = int.from_bytes(self.data[self.offset:end], byteorder="little")
        self.offset = end
        return value

    def read_bytes(self, field_name: str) -> bytes:
        size = self.read_uint(self.machine_width, f"{field_name} length")
        if size > self.remaining:
            raise ValueError(
                f"{field_name} length {size} exceeds the {self.remaining} "
                "bytes remaining in the SEA blob"
            )
        end = self.offset + size
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def read_string(self, field_name: str) -> str:
        value = self.read_bytes(field_name)
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{field_name} is not valid UTF-8") from exc

    def read_count(self, field_name: str) -> int:
        value = self.read_uint(self.machine_width, field_name)
        if value > self.remaining // self.machine_width:
            raise ValueError(
                f"{field_name} {value} cannot fit in the {self.remaining} "
                "bytes remaining in the SEA blob"
            )
        return value


def _parse_sea_blob(
    data: bytes, machine_width: int, layout: SeaBlobLayout
) -> SeaBlob:
    reader = _BlobReader(data, machine_width)
    magic = reader.read_uint(4, "magic")
    if magic != NODE_SEA_MAGIC_VALUE:
        raise ValueError("Invalid SEA blob magic number")

    flags_value = reader.read_uint(4, "flags")
    known_flags = int(
        SeaBlobFlags.DISABLE_EXPERIMENTAL_SEA_WARNING
        | SeaBlobFlags.USE_SNAPSHOT
        | SeaBlobFlags.USE_CODE_CACHE
        | SeaBlobFlags.INCLUDE_ASSETS
        | SeaBlobFlags.INCLUDE_EXEC_ARGV
    )
    if flags_value & ~known_flags:
        raise ValueError(f"SEA blob has unknown flags 0x{flags_value:x}")
    flags = SeaBlobFlags(flags_value)

    exec_argv_extension = None
    main_code_format = None
    if layout != SeaBlobLayout.LEGACY:
        extension_value = reader.read_uint(1, "exec argv extension")
        try:
            exec_argv_extension = SeaExecArgvExtension(extension_value)
        except ValueError as exc:
            raise ValueError(
                f"Unknown SEA exec argv extension {extension_value}"
            ) from exc
    elif flags & SeaBlobFlags.INCLUDE_EXEC_ARGV:
        raise ValueError("Legacy SEA blobs cannot contain embedded exec argv")

    if layout == SeaBlobLayout.MAIN_CODE_FORMAT:
        format_value = reader.read_uint(1, "main code format")
        try:
            main_code_format = SeaMainCodeFormat(format_value)
        except ValueError as exc:
            raise ValueError(f"Unknown SEA main code format {format_value}") from exc

    code_path = reader.read_string("code path")
    if not code_path:
        raise ValueError("SEA code path is empty")
    sea_resource = reader.read_bytes("main code or snapshot")

    code_cache = None
    if flags & SeaBlobFlags.USE_CODE_CACHE:
        code_cache = reader.read_bytes("code cache")

    assets: Dict[str, bytes] = {}
    if flags & SeaBlobFlags.INCLUDE_ASSETS:
        n_assets = reader.read_count("asset count")
        for _ in range(n_assets):
            asset_name = reader.read_string("asset name")
            if asset_name in assets:
                raise ValueError(f"Duplicate SEA asset name: {asset_name!r}")
            assets[asset_name] = reader.read_bytes(
                f"asset {asset_name!r} content"
            )

    exec_argv: list[str] = []
    if flags & SeaBlobFlags.INCLUDE_EXEC_ARGV:
        n_args = reader.read_count("exec argv count")
        for _ in range(n_args):
            exec_argv.append(reader.read_string("exec argv entry"))

    if reader.remaining:
        raise ValueError(
            f"SEA blob has {reader.remaining} trailing byte(s) after its payload"
        )

    return SeaBlob(
        magic=magic,
        flags=flags,
        machine_width=machine_width,
        code_path=code_path,
        sea_resource=sea_resource,
        code_cache=code_cache,
        assets=assets,
        layout=layout,
        exec_argv_extension=exec_argv_extension,
        main_code_format=main_code_format,
        exec_argv=exec_argv,
        blob_raw=data,
    )


def deserialize_sea_blob(
    data: bytes,
    machine_width: int,
    layout: SeaBlobLayout | None = None,
) -> SeaBlob:
    """Deserialize one complete Node.js SEA preparation blob.

    Node does not store a format version in the blob. When no layout is
    supplied, detect it by trying each known header and requiring a strict,
    bounds-checked parse that consumes the blob exactly.
    """
    if layout is not None:
        return _parse_sea_blob(data, machine_width, layout)

    errors = []
    layouts = (
        SeaBlobLayout.MAIN_CODE_FORMAT,
        SeaBlobLayout.EXEC_ARGV,
        SeaBlobLayout.LEGACY,
    )
    for candidate in layouts:
        try:
            return _parse_sea_blob(data, machine_width, candidate)
        except ValueError as exc:
            errors.append(f"{candidate.value}: {exc}")
    raise ValueError(
        "Unsupported or malformed SEA blob (" + "; ".join(errors) + ")"
    )


def _append_view(output: bytearray, value: bytes, machine_width: int) -> None:
    output.extend(len(value).to_bytes(machine_width, byteorder="little"))
    output.extend(value)


def serialize_sea_blob(blob: SeaBlob) -> bytes:
    if blob.magic != NODE_SEA_MAGIC_VALUE:
        raise ValueError("Invalid SEA blob magic number")
    if blob.machine_width not in (4, 8):
        raise ValueError(f"Unsupported machine width: {blob.machine_width}")

    assets = blob.assets or {}
    output = bytearray()
    output.extend(blob.magic.to_bytes(4, byteorder="little"))
    output.extend(int(blob.flags).to_bytes(4, byteorder="little"))

    if blob.layout != SeaBlobLayout.LEGACY:
        if blob.exec_argv_extension is None:
            raise ValueError("Modern SEA blobs require an exec argv extension")
        output.extend(int(blob.exec_argv_extension).to_bytes(1, byteorder="little"))
    elif blob.flags & SeaBlobFlags.INCLUDE_EXEC_ARGV:
        raise ValueError("Legacy SEA blobs cannot contain embedded exec argv")

    if blob.layout == SeaBlobLayout.MAIN_CODE_FORMAT:
        if blob.main_code_format is None:
            raise ValueError("This SEA layout requires a main code format")
        output.extend(int(blob.main_code_format).to_bytes(1, byteorder="little"))

    _append_view(output, blob.code_path.encode("utf-8"), blob.machine_width)
    _append_view(output, blob.sea_resource, blob.machine_width)

    if blob.flags & SeaBlobFlags.USE_CODE_CACHE:
        if blob.code_cache is None:
            raise ValueError("SEA flags specify a code cache, but none is present")
        _append_view(output, blob.code_cache, blob.machine_width)
    elif blob.code_cache is not None:
        raise ValueError("SEA blob has a code cache without the code-cache flag")

    if blob.flags & SeaBlobFlags.INCLUDE_ASSETS:
        output.extend(len(assets).to_bytes(blob.machine_width, "little"))
        for asset_name, asset_data in assets.items():
            _append_view(output, asset_name.encode("utf-8"), blob.machine_width)
            _append_view(output, asset_data, blob.machine_width)
    elif assets:
        raise ValueError("SEA blob has assets without the include-assets flag")

    if blob.flags & SeaBlobFlags.INCLUDE_EXEC_ARGV:
        output.extend(len(blob.exec_argv).to_bytes(blob.machine_width, "little"))
        for arg in blob.exec_argv:
            _append_view(output, arg.encode("utf-8"), blob.machine_width)
    elif blob.exec_argv:
        raise ValueError("SEA blob has exec argv without the include-exec-argv flag")

    return bytes(output)


class SeaBinary:
    def __init__(self, target_binary: Path):
        self.target_binary = target_binary
        with open(target_binary, "rb") as f:
            self.data = f.read()

    def _file_type(self) -> SeaBinaryType | None:
        if self.data.startswith(b"\x7fELF"):
            return SeaBinaryType.ELF
        if self.data.startswith(b"MZ"):
            return SeaBinaryType.PE
        macho_magics = (
            b"\xcf\xfa\xed\xfe",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xfe\xed\xfa\xce",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        )
        if self.data.startswith(macho_magics):
            return SeaBinaryType.MACHO
        return None

    @staticmethod
    def _elf_endian(elf: lief.ELF.Binary) -> str:
        if elf.header.identity_data == lief.ELF.Header.ELF_DATA.LSB:
            return "little"
        if elf.header.identity_data == lief.ELF.Header.ELF_DATA.MSB:
            return "big"
        raise ValueError("Unsupported ELF byte order")

    @staticmethod
    def _elf_notes(
        contents: bytes, byteorder: str
    ) -> Iterator[Tuple[int, int, int, int, bytes, bytes]]:
        offset = 0
        while offset < len(contents):
            if not any(contents[offset:]):
                return
            if len(contents) - offset < 12:
                raise ValueError("Truncated ELF note header")
            note_offset = offset
            name_size = int.from_bytes(contents[offset:offset + 4], byteorder)
            desc_size = int.from_bytes(contents[offset + 4:offset + 8], byteorder)
            offset += 12
            name_end = offset + name_size
            if name_end > len(contents):
                raise ValueError("Truncated ELF note name")
            name = contents[offset:name_end]
            desc_offset = (name_end + 3) & ~3
            desc_end = desc_offset + desc_size
            if desc_end > len(contents):
                raise ValueError("Truncated ELF note descriptor")
            desc = contents[desc_offset:desc_end]
            next_offset = (desc_end + 3) & ~3
            if next_offset > len(contents):
                raise ValueError("Truncated ELF note padding")
            yield (
                note_offset,
                desc_offset,
                desc_end,
                next_offset,
                name,
                desc,
            )
            offset = next_offset

    def _extract_elf_blob(self) -> Tuple[lief.ELF.Binary, bytes]:
        elf = lief.ELF.parse(str(self.target_binary))
        if not elf:
            raise ValueError("Failed to parse ELF binary")
        byteorder = self._elf_endian(elf)
        for section in elf.sections:
            if section.type != lief.ELF.Section.TYPE.NOTE:
                continue
            contents = bytes(section.content)
            for _, _, _, _, name, desc in self._elf_notes(contents, byteorder):
                if name.rstrip(b"\x00") == b"NODE_SEA_BLOB":
                    if not desc.startswith(NODE_SEA_MAGIC):
                        raise ValueError("ELF SEA note has an invalid magic number")
                    return elf, desc
        raise ValueError("SEA resource not found in ELF binary")

    def _extract_pe_blob(self) -> Tuple[lief.PE.Binary, bytes]:
        pe = lief.PE.parse(str(self.target_binary))
        if not pe:
            raise ValueError("Failed to parse PE binary")
        if not pe.resources or len(pe.resources.childs) == 0:
            raise ValueError("No resources found in PE binary, this is not a SEA")
        for directory in pe.resources.childs:
            for leaf in directory.childs:
                if leaf.name == "NODE_SEA_BLOB":
                    if not leaf.childs:
                        raise ValueError("PE SEA resource has no data entry")
                    return pe, bytes(leaf.childs[0].content)
        raise ValueError("SEA resource not found in PE binary")

    def _extract_macho_blob(self) -> Tuple[lief.MachO.Binary, bytes]:
        fat = lief.MachO.parse(str(self.target_binary))
        if not fat:
            raise ValueError("Failed to parse Mach-O binary")
        for index in range(len(fat)):
            macho = fat.at(index)
            for section in macho.sections:
                if section.name == "__NODE_SEA_BLOB":
                    return macho, bytes(section.content)
        raise ValueError("SEA resource not found in Mach-O binary")

    @staticmethod
    def _macho_machine_width(macho: lief.MachO.Binary) -> int:
        if macho.header.magic in (
            lief.MachO.MACHO_TYPES.MAGIC_64,
            lief.MachO.MACHO_TYPES.CIGAM_64,
        ):
            return 8
        if macho.header.magic in (
            lief.MachO.MACHO_TYPES.MAGIC,
            lief.MachO.MACHO_TYPES.CIGAM,
        ):
            return 4
        raise ValueError("Unsupported Mach-O class")

    def unpack_sea_blob(self) -> SeaBlob:
        file_type = self._file_type()
        if file_type == SeaBinaryType.ELF:
            elf, blob = self._extract_elf_blob()
            if elf.header.identity_class == lief.ELF.Header.CLASS.ELF32:
                machine_width = 4
            elif elf.header.identity_class == lief.ELF.Header.CLASS.ELF64:
                machine_width = 8
            else:
                raise ValueError("Unsupported ELF class")
            print(f"\t+ Loaded ELF-SEA, machine type: {elf.header.identity_class.name}")
        elif file_type == SeaBinaryType.PE:
            pe, blob = self._extract_pe_blob()
            if pe.header.machine in (
                lief.PE.Header.MACHINE_TYPES.AMD64,
                lief.PE.Header.MACHINE_TYPES.IA64,
                lief.PE.Header.MACHINE_TYPES.ARM64,
            ):
                machine_width = 8
            elif pe.header.machine in (
                lief.PE.Header.MACHINE_TYPES.I386,
                lief.PE.Header.MACHINE_TYPES.ARM,
                lief.PE.Header.MACHINE_TYPES.ARMNT,
            ):
                machine_width = 4
            else:
                raise ValueError("Unsupported PE machine type")
            print(f"\t+ Loaded PE-SEA, machine type: {pe.header.machine.name}")
        elif file_type == SeaBinaryType.MACHO:
            macho, blob = self._extract_macho_blob()
            machine_width = self._macho_machine_width(macho)
            print(f"\t+ Loaded MACHO-SEA, machine type: {macho.header.cpu_type.name}")
        else:
            raise ValueError("Unsupported binary type")

        return deserialize_sea_blob(blob, machine_width)

    def _repack_elf_blob(self, repacked: bytes) -> None:
        elf = lief.ELF.parse(str(self.target_binary))
        if not elf:
            raise ValueError("Failed to parse ELF binary")
        byteorder = self._elf_endian(elf)
        for section in elf.sections:
            if section.type != lief.ELF.Section.TYPE.NOTE:
                continue
            contents = bytes(section.content)
            for note in self._elf_notes(contents, byteorder):
                note_offset, desc_offset, _, next_offset, name, desc = note
                if name.rstrip(b"\x00") != b"NODE_SEA_BLOB":
                    continue
                if not desc.startswith(NODE_SEA_MAGIC):
                    raise ValueError("ELF SEA note has an invalid magic number")
                header = bytearray(contents[note_offset:note_offset + 12])
                header[4:8] = len(repacked).to_bytes(4, byteorder)
                name_and_padding = contents[note_offset + 12:desc_offset]
                padding = b"\x00" * ((-len(repacked)) & 3)
                new_contents = (
                    contents[:note_offset]
                    + header
                    + name_and_padding
                    + repacked
                    + padding
                    + contents[next_offset:]
                )
                section.content = list(new_contents)
                elf.write(str(self.target_binary))
                return
        raise ValueError("SEA resource not found in ELF binary")

    def _repack_pe_blob(self, repacked: bytes) -> None:
        pe = lief.PE.parse(str(self.target_binary))
        if not pe:
            raise ValueError("Failed to parse PE binary")
        if not pe.resources or len(pe.resources.childs) == 0:
            raise ValueError("No resources found in PE binary, this is not a SEA")
        for directory in pe.resources.childs:
            for leaf in directory.childs:
                if leaf.name == "NODE_SEA_BLOB":
                    if not leaf.childs:
                        raise ValueError("PE SEA resource has no data entry")
                    leaf.childs[0].content = list(repacked)
                    pe.write(str(self.target_binary))
                    return
        raise ValueError("SEA resource not found in PE binary")

    def _repack_macho_blob(self, repacked: bytes) -> None:
        fat = lief.MachO.parse(str(self.target_binary))
        if not fat:
            raise ValueError("Failed to parse Mach-O binary")
        for index in range(len(fat)):
            macho = fat.at(index)
            for section in macho.sections:
                if section.name == "__NODE_SEA_BLOB":
                    growth = len(repacked) - section.size
                    if growth > 0:
                        raise ValueError(
                            "Growing a Mach-O SEA blob is not supported; "
                            f"the replacement is {growth} byte(s) too large"
                        )
                    section.content = list(repacked)
                    fat.write(str(self.target_binary))
                    return
        raise ValueError("SEA resource not found in Mach-O binary")

    def repack_sea_blob(self, blob: SeaBlob, stomp_script: bool) -> None:
        if blob.sea_resource.startswith(b"\x19\xdaC\x01"):
            print("\t+ Detected v8 snapshot blob, enabling snapshot execution...")
            blob.flags |= SeaBlobFlags.USE_SNAPSHOT

        if blob.flags & SeaBlobFlags.USE_CODE_CACHE:
            if stomp_script:
                if not blob.code_cache:
                    raise ValueError(
                        "Stomping is not supported for this SEA blob, "
                        "there is no code cache"
                    )
                blob.code_cache = invalidate_code_cache(
                    blob.sea_resource, blob.code_cache
                )
            else:
                print("\t+ Detected stale code cache, clearing it...")
                blob.flags &= ~SeaBlobFlags.USE_CODE_CACHE
                blob.code_cache = None
        elif stomp_script:
            raise ValueError(
                "Script stomping is not supported in this SEA blob, "
                "there is no code cache"
            )

        repacked = serialize_sea_blob(blob)
        file_type = self._file_type()
        if file_type == SeaBinaryType.ELF:
            self._repack_elf_blob(repacked)
        elif file_type == SeaBinaryType.PE:
            self._repack_pe_blob(repacked)
        elif file_type == SeaBinaryType.MACHO:
            self._repack_macho_blob(repacked)
        else:
            raise ValueError("Unsupported binary type")
