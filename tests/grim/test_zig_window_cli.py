from __future__ import annotations

import subprocess

import crimson.dbg.record as dbg_record


def test_zig_window_is_installed_by_default_build() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    window_bin = dbg_record._ZIG_ROOT / "zig-out" / "bin" / "crimson-zig-window"
    result = subprocess.run(
        [str(window_bin), "--help"],
        cwd=dbg_record._REPO_ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "usage: crimson-zig-window [--demo] [--no-intro]" in result.stderr
