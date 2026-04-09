from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode

from ._helpers import build_replay, write_replay


def test_zig_replay_verify_respects_max_ticks_partial_run_contract(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json", "--max-ticks", "2"],
    )

    assert zig_payload == python_payload


def test_zig_replay_verify_matches_python_full_payload_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_verify(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_verify(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def _run_python_replay_verify(args: list[str]) -> dict[str, object]:
    runner = CliRunner()
    result = runner.invoke(app, ["replay", "verify", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_zig_replay_verify(args: list[str]) -> dict[str, object]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    verify_run = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "verify", *args],
        cwd=dbg_record._REPO_ROOT,
    )
    assert verify_run.returncode == 0, dbg_record._command_detail(verify_run)
    return json.loads(verify_run.stdout)
