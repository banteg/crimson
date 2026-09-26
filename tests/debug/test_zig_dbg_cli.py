from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.sim.run_spec import RunSpec
from tests.replay.cli._helpers import record_bot_replay, write_replay

_BOT_TRACE_CASES = {
    # Ping-pong creatures take projectile damage without the heading-jitter
    # draw; den children get their random tints.
    "quest-1.5": lambda: record_bot_replay(
        RunSpec(game_mode_id=GameMode.QUESTS, seed=3, quest_level=QuestLevel.parse("1.5")),
        max_ticks=200,
    ),
    # Rocket Minigun: one muzzle sprite, rocket trails and detonation fields.
    "quest-4.1": lambda: record_bot_replay(
        RunSpec(game_mode_id=GameMode.QUESTS, seed=1, quest_level=QuestLevel.parse("4.1")),
        max_ticks=200,
    ),
    # Rush edge spawns place their y coordinate in double precision.
    "rush": lambda: record_bot_replay(RunSpec(game_mode_id=GameMode.RUSH, seed=1), max_ticks=160),
    # Typ-o spawns and shotgun pellet rolls are computed in double precision.
    "typo": lambda: record_bot_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1), max_ticks=90, type_every=12),
}


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


@pytest.mark.parametrize("case", sorted(_BOT_TRACE_CASES))
def test_zig_dbg_record_matches_python_trace_for_bot_runs(tmp_path: Path, case: str) -> None:
    replay_path = write_replay(tmp_path, replay=_BOT_TRACE_CASES[case](), name=f"{case}.crd")
    runner = CliRunner()
    traces = {}
    for impl in ("python", "zig"):
        traces[impl] = tmp_path / f"{case}.{impl}.cdt"
        record = runner.invoke(app, ["dbg", "record", str(replay_path), "--impl", impl, "--out", str(traces[impl])])
        assert record.exit_code == 0, record.output

    diff = runner.invoke(app, ["dbg", "diff", str(traces["python"]), str(traces["zig"])])

    assert diff.exit_code == 0, diff.output
    assert diff.output.startswith("result=ok"), diff.output


def _run_zig_dbg(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "dbg", *args],
        cwd=dbg_record._REPO_ROOT,
    )
