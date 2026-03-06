from __future__ import annotations

import json
from pathlib import Path

import msgspec
from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot
from crimson.sim.input_providers import PerkPickCommand
from crimson.weapons import WeaponId

from ._helpers import build_replay, inject_tick_commands, run_verify_playback, write_replay


def test_replay_verify_human_success_outputs_run_stats(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output
    assert "ticks=" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_json_output_payload_ok(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 2
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert payload["score_claim"] is None
    assert payload["run_result"]["ticks"] == 2
    assert payload["run_result"]["score_xp"] == 0


def test_replay_verify_checks_header_claimed_stats_match(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    expected = run_verify_playback(replay)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=int(expected.ticks),
                elapsed_ms=int(expected.elapsed_ms),
                score_xp=int(expected.score_xp),
                kills=int(expected.creature_kill_count),
                most_used_weapon_id=WeaponId(expected.most_used_weapon_id),
                shots_fired=int(expected.shots_fired),
                shots_hit=int(expected.shots_hit),
            ),
        ),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-claimed.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["header_claim"]["match"] is True
    assert payload["header_claim"]["mismatched_fields"] == []


def test_replay_verify_reports_header_claimed_stats_mismatch(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=2,
                elapsed_ms=1,
                score_xp=999,
                kills=4,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=2,
                shots_hit=1,
            ),
        ),
    )
    replay_path = write_replay(tmp_path, replay=replay, name="survival-claimed-bad.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "header_stats_mismatch"
    assert payload["header_claim"]["match"] is False
    assert "elapsed_ms" in payload["header_claim"]["mismatched_fields"]
    assert "score_xp" in payload["header_claim"]["mismatched_fields"]
    assert payload["score_claim"] is None


def test_replay_verify_rejects_removed_submitted_score_option(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--submitted-score",
            "0",
        ],
    )

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "No such option" in output
    assert "--submitted-score" in output


def test_replay_verify_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 0


def test_replay_verify_rejects_removed_lenient_events_option(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--lenient-events"])

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "No such option" in output
    assert "--lenient-events" in output


def test_replay_verify_json_out_works_for_human_and_json_output(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    human_out = tmp_path / "verify-human.json"
    json_out = tmp_path / "verify-json.json"

    human_result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--json-out",
            str(human_out),
        ],
    )
    assert human_result.exit_code == 0, human_result.output
    assert "json_report=" in human_result.output
    assert json.loads(human_out.read_text(encoding="utf-8"))["status"] == "ok"

    json_result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--json-out",
            str(json_out),
        ],
    )
    assert json_result.exit_code == 0, json_result.output
    stdout_payload = json.loads(json_result.output)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert stdout_payload["status"] == "ok"
    assert file_payload == stdout_payload
