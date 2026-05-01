from __future__ import annotations

import subprocess

from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app


def test_zig_dbg_verify_matches_python_contract() -> None:
    runner = CliRunner()
    python_result = runner.invoke(app, ["dbg", "verify"])
    assert python_result.exit_code == 0, python_result.output

    zig_result = _run_zig_dbg(["verify"])

    assert zig_result.returncode == 0, dbg_record._command_detail(zig_result)
    assert zig_result.stderr == ""
    assert zig_result.stdout == python_result.output


def test_zig_dbg_verify_rejects_extra_args() -> None:
    result = _run_zig_dbg(["verify", "extra"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid dbg verify args: dbg verify does not take arguments" in result.stderr


def _run_zig_dbg(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "dbg", *args],
        cwd=dbg_record._REPO_ROOT,
    )
