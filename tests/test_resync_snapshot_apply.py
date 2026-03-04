from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.rollback_resync_v5 import (
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    encode_mode_snapshot,
)
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "assets"


def test_survival_apply_resync_snapshot_restores_mode_state() -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    mode._survival.elapsed_ms = 0.0
    mode._survival.stage = 0
    mode._survival.spawn_cooldown = 0.0
    mode._spawn_state.stage = 0
    mode._spawn_state.spawn_cooldown_ms = 0.0

    snapshot = SurvivalStateSnapshotV2(
        tick_index=100,
        runtime_state=SurvivalRuntimeSnapshotV2(
            elapsed_ms=5000.0,
            stage=3,
            spawn_cooldown_ms=1200.0,
            perk_pending_count=2,
        ),
    )
    mode._apply_resync_snapshot(snapshot)

    assert mode._survival.elapsed_ms == 5000.0
    assert mode._survival.stage == 3
    assert mode._survival.spawn_cooldown == 1200.0
    assert mode._spawn_state.stage == 3
    assert mode._spawn_state.spawn_cooldown_ms == 1200.0


def test_rush_apply_resync_snapshot_restores_mode_state() -> None:
    mode = RushMode(ViewContext(assets_dir=_assets_dir()))
    mode._rush.elapsed_ms = 0.0
    mode._rush.spawn_cooldown_ms = 0.0
    mode._spawn_state.spawn_cooldown_ms = 0.0
    mode.creatures.kill_count = 0

    snapshot = RushStateSnapshotV2(
        tick_index=200,
        runtime_state=RushRuntimeSnapshotV2(
            elapsed_ms=8000.0,
            spawn_cooldown_ms=500.0,
            kill_count=42,
        ),
    )
    mode._apply_resync_snapshot(snapshot)

    assert mode._rush.elapsed_ms == 8000.0
    assert mode._rush.spawn_cooldown_ms == 500.0
    assert mode._spawn_state.spawn_cooldown_ms == 500.0
    assert mode.creatures.kill_count == 42


def test_consume_net_runtime_recovery_applies_snapshot_and_resets_runner(mocker) -> None:
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()))
    mode._survival.elapsed_ms = 0.0
    mode._survival.stage = 0

    snapshot = SurvivalStateSnapshotV2(
        tick_index=8,
        runtime_state=SurvivalRuntimeSnapshotV2(
            elapsed_ms=3000.0,
            stage=2,
            spawn_cooldown_ms=600.0,
            perk_pending_count=0,
        ),
    )
    payload = encode_mode_snapshot(snapshot=snapshot)

    mock_runtime = MagicMock()
    mock_runtime.pop_rollback_from.return_value = None
    mock_runtime.pop_resync_snapshot.return_value = (8, payload)
    mock_runtime.error = ""
    mode._rollback_runtime = mock_runtime

    reset_spy = mocker.patch.object(mode, "_reset_tick_runner_state")
    mode._consume_net_runtime_recovery(mode_name="survival")

    assert mode._survival.elapsed_ms == 3000.0
    assert mode._survival.stage == 2
    assert mode._survival.spawn_cooldown == 600.0
    mock_runtime.mark_resync_applied.assert_called_once_with(8)
    reset_spy.assert_called_once()
