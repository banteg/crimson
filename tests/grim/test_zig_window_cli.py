from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import crimson.dbg.record as dbg_record


@pytest.fixture(scope="module")
def window_bin() -> Path:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)
    return dbg_record._ZIG_ROOT / "zig-out" / "bin" / "crimson-zig-window"


def test_zig_window_is_installed_by_default_build(window_bin: Path) -> None:
    result = subprocess.run(
        [str(window_bin), "--help"],
        cwd=dbg_record._REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert "usage: crimson-zig-window [--demo] [--debug] [--preserve-bugs] [--no-intro] [--seed N]" in result.stderr
    assert "[--smoke-start]" in result.stderr


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--start-mode", "survival"], "mode=survival player_count=1 quest_level=none"),
        (["--start-mode", "rush", "--players", "2"], "mode=rush player_count=2 quest_level=none"),
        (["--start-mode", "quests", "--quest-level", "2.4"], "mode=quests player_count=1 quest_level=2.4"),
        (["--start-mode", "typo", "--players", "4"], "mode=typo player_count=1 quest_level=none"),
        (["--start-mode", "tutorial", "--players", "4"], "mode=tutorial player_count=1 quest_level=none"),
    ],
)
def test_zig_window_smoke_starts_direct_modes(
    window_bin: Path,
    tmp_path: Path,
    args: list[str],
    expected: str,
) -> None:
    result = subprocess.run(
        [
            str(window_bin),
            "--smoke-start",
            "--base-dir",
            str(tmp_path),
            "--seed",
            "0xBEEF",
            *args,
        ],
        cwd=dbg_record._REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    assert result.stderr == ""
    assert result.stdout.startswith("ok: ")
    assert expected in result.stdout
    assert "seed=48879" in result.stdout
