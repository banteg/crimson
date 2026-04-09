from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkMenuOpenCommand

from ._helpers import build_replay, inject_tick_commands, write_replay


def test_zig_replay_info_matches_python_json_payload_on_simple_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    python_payload = _run_python_replay_info(
        [str(replay_path), "--format", "json"],
    )
    zig_payload = _run_zig_replay_info(
        [str(replay_path), "--format", "json"],
    )

    assert zig_payload == python_payload


def test_zig_replay_info_matches_python_verbose_player_filter_payload(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1, player_count=2)
    inject_tick_commands(
        replay,
        0,
        [
            PerkMenuOpenCommand(player_index=0),
            PerkMenuOpenCommand(player_index=1),
        ],
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-2p.crd")

    python_payload = _run_python_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
            "--player-index",
            "1",
        ],
    )
    zig_payload = _run_zig_replay_info(
        [
            str(replay_path),
            "--format",
            "json",
            "--verbose",
            "--player-index",
            "1",
        ],
    )

    assert zig_payload == python_payload


def _run_python_replay_info(args: list[str]) -> dict[str, object]:
    runner = CliRunner()
    result = runner.invoke(app, ["replay", "info", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_zig_replay_info(args: list[str]) -> dict[str, object]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    info_run = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "info", *args],
        cwd=dbg_record._REPO_ROOT,
    )
    assert info_run.returncode == 0, dbg_record._command_detail(info_run)
    return json.loads(info_run.stdout)
