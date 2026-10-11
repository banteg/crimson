from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from crimson.cli.app import app
from crimson.game_modes import GameMode
from tests.replay.cli._helpers import build_replay as _build_replay
from tests.replay.cli._helpers import write_checkpoint_sidecar as _write_checkpoint_sidecar
from tests.replay.cli._helpers import write_replay as _write_replay


def test_replay_verify_checkpoints_preserves_success_behavior(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay, mutate_checkpoint=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "checkpoint mismatch at tick=0" in result.output
    assert "first state diff: score_xp expected=999999 actual=0" in result.output


def test_replay_diff_checkpoints_still_reports_success(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = _write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "actual.crd.chk"
    sidecar_b.write_bytes(sidecar_a.read_bytes())
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "diff-checkpoints", str(sidecar_a), str(sidecar_b)],
    )

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
