from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.rollback_resync_v5 import (
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    encode_mode_snapshot,
)
from crimson.sim.clock import FixedStepClock
from crimson.sim.input_providers import LocalInputProvider
from crimson.sim.sessions import DeterministicSession
from crimson.sim.tick_runner import TickRunner, TickRunnerConfig
from grim.view import ViewContext

if TYPE_CHECKING:
    from crimson.net.rollback_runtime import RollbackRuntime


def _assets_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "assets"


class _RollbackRuntimeStub:
    def __init__(self, *, tick_index: int, payload: bytes) -> None:
        self._pending = (int(tick_index), payload)
        self.error = ""
        self.marked_resync_ticks: list[int] = []

    def pop_rollback_from(self) -> None:
        return None

    def pop_resync_snapshot(self) -> tuple[int, bytes] | None:
        pending = self._pending
        self._pending = None
        return pending

    def mark_resync_applied(self, tick_index: int) -> None:
        self.marked_resync_ticks.append(int(tick_index))


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


def test_consume_net_runtime_recovery_applies_snapshot_and_resets_runner() -> None:
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
    mode._rollback_runtime = cast("RollbackRuntime", _RollbackRuntimeStub(tick_index=8, payload=payload))
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    input_provider = LocalInputProvider(player_count=1, build_inputs=lambda _frame_ctx: [])
    mode._tick_input_provider = input_provider
    mode._tick_runner = TickRunner(
        session=session,
        input_provider=input_provider,
        config=TickRunnerConfig(),
    )
    mode._tick_runner_session = session
    mode._tick_runner_is_networked = True
    mode._tick_runner_network_role = "host"
    mode._tick_runner_frame_index = 13
    mode._tick_runner_next_tick_index = 42
    mode._tick_runner_local_clock = FixedStepClock(tick_rate=60)
    mode._consume_net_runtime_recovery(mode_name="survival")

    assert mode._survival.elapsed_ms == 3000.0
    assert mode._survival.stage == 2
    assert mode._survival.spawn_cooldown == 600.0
    runtime = mode._rollback_runtime
    assert isinstance(runtime, _RollbackRuntimeStub)
    assert runtime.marked_resync_ticks == [8]
    assert mode._tick_input_provider is None
    assert mode._tick_runner is None
    assert mode._tick_runner_session is None
    assert mode._tick_runner_is_networked is False
    assert mode._tick_runner_network_role == ""
    assert mode._tick_runner_frame_index == 0
    assert mode._tick_runner_next_tick_index == 0
    assert mode._tick_runner_local_clock is None
