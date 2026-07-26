from __future__ import annotations

import subprocess

import crimson.dbg.record as dbg_record


def test_zig_asset_smoke_is_installed_by_default_build() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    asset_smoke_bin = dbg_record._ZIG_ROOT / "zig-out" / "bin" / "crimson-zig-asset-smoke"
    result = subprocess.run(
        [str(asset_smoke_bin), "--help"],
        cwd=dbg_record._REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "crimson-zig-asset-smoke [assets-dir]" in result.stdout
    assert "Runs a local decode smoke pass over crimson.paq" in result.stdout


def test_zig_asset_extract_is_installed_by_default_build() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    asset_extract_bin = dbg_record._ZIG_ROOT / "zig-out" / "bin" / "crimson-zig-asset-extract"
    result = subprocess.run(
        [str(asset_extract_bin), "--help"],
        cwd=dbg_record._REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "crimson-zig-asset-extract <game-dir> <assets-dir>" in result.stdout
    assert "Extracts all .paq files under game-dir into assets-dir" in result.stdout
