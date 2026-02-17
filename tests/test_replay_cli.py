from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader, ReplayRecorder, dump_replay
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    default_checkpoints_path,
    dump_checkpoints_file,
)
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _build_replay(*, mode: GameMode, ticks: int, seed: int = 0xBEEF) -> Replay:
    header = ReplayHeader(
        game_mode_id=int(mode),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return recorder.finish()


def _write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def _write_checkpoint_sidecar(replay_path: Path, replay: Replay, *, mutate_command_hash: bool = False) -> Path:
    checkpoint_ticks = {0}
    checkpoints = []
    run_replay(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    if mutate_command_hash:
        checkpoints[0] = replace(checkpoints[0], command_hash="deadbeef")
    replay_sha256 = hashlib.sha256(replay_path.read_bytes()).hexdigest()
    payload = ReplayCheckpoints(
        version=int(FORMAT_VERSION),
        replay_sha256=str(replay_sha256),
        sample_rate=1,
        checkpoints=list(checkpoints),
    )
    sidecar_path = default_checkpoints_path(replay_path)
    dump_checkpoints_file(sidecar_path, payload)
    return sidecar_path


def test_replay_list_shows_replays_under_base_dir(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    _write_replay(tmp_path / "replays", replay=replay, name="zeta.crdemo.gz")
    _write_replay(tmp_path / "replays", replay=replay, name="alpha.crdemo.gz")
    _write_replay(tmp_path / "replays" / "nested", replay=replay, name="nested.crdemo.gz")
    (tmp_path / "replays" / "ignore.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    lines = [line.strip() for line in result.output.splitlines() if line.strip()]
    assert lines == ["alpha.crdemo.gz", "nested/nested.crdemo.gz", "zeta.crdemo.gz", "count=3"]


def test_replay_list_reports_when_no_replays_found(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    assert f"no replay files found under {tmp_path / 'replays'}" in result.output


def test_replay_verify_human_success_outputs_run_stats(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output
    assert "ticks=" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_json_output_payload_ok(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert isinstance(payload["replay_sha256"], str)
    assert payload["score_claim"] is None
    assert payload["run_result"]["ticks"] == 2
    assert payload["run_result"]["score_xp"] == 0


def test_replay_verify_submitted_score_match_exit_zero(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            "0",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["score_claim"]["metric"] == "score_xp"
    assert payload["score_claim"]["match"] is True


def test_replay_verify_submitted_score_mismatch_exit_three(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            "1",
        ],
    )

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "score_mismatch"
    assert payload["score_claim"]["metric"] == "score_xp"
    assert payload["score_claim"]["match"] is False


def test_replay_verify_auto_metric_uses_elapsed_ms_for_rush(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.RUSH, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="rush.crdemo.gz")
    expected_elapsed_ms = run_replay(replay).elapsed_ms
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            str(expected_elapsed_ms),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["score_claim"]["metric"] == "elapsed_ms"
    assert payload["score_claim"]["simulated_value"] == int(expected_elapsed_ms)
    assert payload["score_claim"]["match"] is True


def test_replay_verify_json_out_works_for_human_and_json_output(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
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


def test_replay_verify_rejects_checkpoints_option(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--checkpoints",
            str(tmp_path / "expected.checkpoints.json.gz"),
        ],
    )

    assert result.exit_code == 2
    assert "No such option: --checkpoints" in result.output


def test_replay_verify_checkpoints_preserves_success_behavior(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    _write_checkpoint_sidecar(replay_path, replay)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    _write_checkpoint_sidecar(replay_path, replay, mutate_command_hash=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "checkpoint command mismatch at tick=0" in result.output


def test_replay_diff_checkpoints_still_reports_success(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crdemo.gz")
    sidecar_a = _write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "actual.checkpoints.json.gz"
    sidecar_b.write_bytes(sidecar_a.read_bytes())
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "diff-checkpoints", str(sidecar_a), str(sidecar_b)],
    )

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
