import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from scallop.cli import _sanitize_output_name, app
from scallop.sea import (
    SeaBinary,
    SeaBlobLayout,
    SeaExecArgvExtension,
    SeaMainCodeFormat,
)


RUN_REAL_SEA_TEST = os.environ.get("SCALLOP_TEST_REAL_SEA") == "1"


def _run(executable: Path) -> str:
    result = subprocess.run(
        [str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _sign_macho(executable: Path) -> None:
    if sys.platform == "darwin":
        subprocess.run(
            ["codesign", "--sign", "-", "--force", str(executable)],
            check=True,
        )


@pytest.mark.skipif(
    not RUN_REAL_SEA_TEST,
    reason="set SCALLOP_TEST_REAL_SEA=1 to build a real Node 26 SEA",
)
def test_real_node_26_sea(tmp_path):
    node = shutil.which("node")
    assert node is not None
    node_version = subprocess.check_output([node, "--version"], text=True)
    assert node_version.startswith("v26."), node_version

    executable = tmp_path / (
        "sea-fixture.exe" if sys.platform == "win32" else "sea-fixture"
    )
    main = tmp_path / "main.mjs"
    asset = tmp_path / "asset.txt"
    config = tmp_path / "sea-config.json"
    main_source = (
        'import { getAsset } from "node:sea";\n'
        'console.log(getAsset("fixture.txt", "utf8"));\n'
    ).encode()
    asset_data = b"node-26-asset"
    main.write_bytes(main_source)
    asset.write_bytes(asset_data)
    config.write_text(
        json.dumps(
            {
                "main": str(main),
                "mainFormat": "module",
                "output": str(executable),
                "disableExperimentalSEAWarning": True,
                "execArgv": ["--no-warnings"],
                "execArgvExtension": "cli",
                "assets": {"fixture.txt": str(asset)},
            }
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [node, f"--build-sea={config}"],
        check=True,
        cwd=tmp_path,
    )
    _sign_macho(executable)
    assert _run(executable) == "node-26-asset\n"

    sea_blob = SeaBinary(executable).unpack_sea_blob()
    assert sea_blob.layout == SeaBlobLayout.MAIN_CODE_FORMAT
    assert sea_blob.exec_argv_extension == SeaExecArgvExtension.CLI
    assert sea_blob.main_code_format == SeaMainCodeFormat.MODULE
    assert sea_blob.sea_resource == main_source
    assert sea_blob.assets == {"fixture.txt": asset_data}
    assert sea_blob.exec_argv == ["--no-warnings"]

    runner = CliRunner()
    result = runner.invoke(app, ["unpack", str(executable)])
    assert result.exit_code == 0, result.output
    unpacked = executable.parent / f"{executable.stem}_unpacked"
    unpacked_main = _sanitize_output_name(
        sea_blob.code_path, "main_resource.bin"
    )
    assert (unpacked / unpacked_main).read_bytes() == main_source
    assert (unpacked / "fixture.txt").read_bytes() == asset_data

    main_repacked = executable.with_name(f"main-repacked{executable.suffix}")
    shutil.copy2(executable, main_repacked)
    main_binary = SeaBinary(main_repacked)
    main_blob = main_binary.unpack_sea_blob()
    main_blob.sea_resource = b'console.log("repacked-main");\n'
    main_binary.repack_sea_blob(main_blob, False)
    _sign_macho(main_repacked)
    assert _run(main_repacked) == "repacked-main\n"

    asset_repacked = executable.with_name(
        f"asset-repacked{executable.suffix}"
    )
    shutil.copy2(executable, asset_repacked)
    asset_binary = SeaBinary(asset_repacked)
    asset_blob = asset_binary.unpack_sea_blob()
    replacement_asset = b"new--26-asset"
    assert len(replacement_asset) == len(asset_data)
    assert asset_blob.assets is not None
    asset_blob.assets["fixture.txt"] = replacement_asset
    asset_binary.repack_sea_blob(asset_blob, False)
    _sign_macho(asset_repacked)
    assert _run(asset_repacked) == "new--26-asset\n"
