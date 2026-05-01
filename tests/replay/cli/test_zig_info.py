from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

import crimson.dbg.record as dbg_record
from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand

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


def test_zig_replay_info_matches_python_json_payload_on_quest_replay(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.QUESTS, ticks=3, quest_level="1.1")
    replay_path = write_replay(tmp_path, replay=replay, name="quest.crd")
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


def test_zig_replay_info_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    python_payload = _run_python_replay_info([str(replay_path), "--format", "json"])
    zig_payload = _run_zig_replay_info([str(replay_path), "--format", "json"])

    assert zig_payload == python_payload


def test_zig_replay_info_writes_json_out_like_python(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    json_out = tmp_path / "reports" / "info.json"

    result = _run_zig_replay_info_process(
        [str(replay_path), "--format", "json", "--json-out", str(json_out)],
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert file_payload == stdout_payload


def test_zig_replay_info_rejects_non_crd_extension(tmp_path: Path) -> None:
    replay_path = tmp_path / "survival.txt"
    replay_path.write_bytes(b"not checked before extension validation")

    result = _run_zig_replay_info_process([str(replay_path), "--format", "json"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "replay info failed: only .crd replay files are currently supported" in result.stderr


def _run_python_replay_info(args: list[str]) -> dict[str, object]:
    runner = CliRunner()
    result = runner.invoke(app, ["replay", "info", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _run_zig_replay_info(args: list[str]) -> dict[str, object]:
    info_run = _run_zig_replay_info_process(args)
    assert info_run.returncode == 0, dbg_record._command_detail(info_run)
    return json.loads(info_run.stdout)


def _run_zig_replay_info_process(args: list[str]) -> subprocess.CompletedProcess[str]:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    return dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "replay", "info", *args],
        cwd=dbg_record._REPO_ROOT,
    )
