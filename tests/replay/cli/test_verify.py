from __future__ import annotations

import hashlib
import json
from pathlib import Path

import msgspec
from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import Replay, encode_replay_payload
from crimson.sim.input_providers import PerkPickCommand

from ._helpers import build_replay, inject_tick_commands, write_replay


def _tamper_result(replay: Replay) -> Replay:
    result = replay.result
    player = msgspec.structs.replace(result.players[0], experience=result.players[0].experience + 999)
    return msgspec.structs.replace(
        replay,
        result=msgspec.structs.replace(result, kills=result.kills + 4, players=(player,)),
    )


def test_replay_verify_human_success_outputs_run_result(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("ok: outcome=incomplete ticks=3/3 ")
    assert f"score_xp={replay.result.players[0].experience}" in result.output
    assert f"kills={replay.result.kills}" in result.output
    assert f"rng_state={replay.result.rng_state}" in result.output


def test_replay_verify_json_output_payload_ok(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 3
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert payload["payload_sha256"] == hashlib.sha256(encode_replay_payload(replay)).hexdigest()
    assert payload["game_version"] == replay.game_version
    assert payload["ticks"] == 2
    assert payload["ticks_simulated"] == 2
    assert payload["result"] == json.loads(msgspec.json.encode(replay.result))
    assert payload["recorded"] == payload["result"]
    assert payload["mismatched_fields"] == []


def test_replay_verify_reports_result_mismatch(tmp_path: Path) -> None:
    replay = _tamper_result(build_replay(mode=GameMode.SURVIVAL, ticks=2))
    replay_path = write_replay(tmp_path, replay=replay, name="survival-tampered.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "result_mismatch"
    assert payload["mismatched_fields"] == ["kills", "players[0].experience"]
    assert payload["recorded"] == json.loads(msgspec.json.encode(replay.result))
    assert payload["result"] != payload["recorded"]

    human = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert human.exit_code == 3, human.output
    assert human.output.startswith("result_mismatch: ")
    assert "; mismatches=kills,players[0].experience" in human.output


def test_replay_verify_max_ticks_prefix_is_partial(tmp_path: Path) -> None:
    replay = _tamper_result(build_replay(mode=GameMode.SURVIVAL, ticks=3))
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(
        app,
        ["replay", "verify", str(replay_path), "--max-ticks", "1", "--format", "json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "partial"
    assert payload["ticks"] == 3
    assert payload["ticks_simulated"] == 1
    assert payload["result"]["outcome"] == "incomplete"
    assert payload["mismatched_fields"] == []


def test_replay_verify_rejects_removed_submitted_score_option(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(app, ["replay", "verify", str(replay_path), "--submitted-score", "0"])

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "No such option" in output
    assert "--submitted-score" in output


def test_replay_verify_rejects_perk_pick_without_pending_perk(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 1
    assert "replay verification failed: tick 0:" in result.output


def test_replay_verify_rejects_removed_lenient_events_option(tmp_path: Path) -> None:
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    result = CliRunner().invoke(app, ["replay", "verify", str(replay_path), "--lenient-events"])

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

    human_result = runner.invoke(app, ["replay", "verify", str(replay_path), "--json-out", str(human_out)])
    assert human_result.exit_code == 0, human_result.output
    assert "json_report=" in human_result.output
    assert json.loads(human_out.read_text(encoding="utf-8"))["status"] == "ok"

    json_result = runner.invoke(
        app,
        ["replay", "verify", str(replay_path), "--format", "json", "--json-out", str(json_out)],
    )
    assert json_result.exit_code == 0, json_result.output
    stdout_payload = json.loads(json_result.output)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert stdout_payload["status"] == "ok"
    assert file_payload == stdout_payload
