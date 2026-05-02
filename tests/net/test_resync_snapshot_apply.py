from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from crimson.creatures.spawn import SpawnId
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.rollback_resync_v5 import (
    QuestsRuntimeSnapshotV2,
    QuestsStateSnapshotV2,
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    encode_mode_snapshot,
)
from crimson.quests.level import QuestLevel
from crimson.quests.types import SpawnEntry
from crimson.sim.clock import FixedStepClock
from crimson.sim.input_providers import LocalInputProvider
from crimson.sim.sessions import DeterministicSession
from crimson.sim.tick_runner import TickRunner, TickRunnerConfig
from grim.geom import Vec2
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.builders.input_providers import StaticLocalInputRuntime

if TYPE_CHECKING:
    from crimson.net.rollback_runtime import RollbackRuntime


def _assets_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "assets"


def _survival_mode(*, config) -> SurvivalMode:
    return SurvivalMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))


def _rush_mode(*, config) -> RushMode:
    return RushMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))


def _quest_mode(*, config) -> QuestMode:
    return QuestMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))


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


def test_survival_apply_resync_snapshot_restores_mode_state(make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    session.elapsed_ms = 0.0
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

    assert session.elapsed_ms == 5000.0
    assert mode._spawn_state.stage == 3
    assert mode._spawn_state.spawn_cooldown_ms == 1200.0


def test_rush_apply_resync_snapshot_restores_mode_state(make_mode_config) -> None:
    mode = _rush_mode(config=make_mode_config(game_mode=GameMode.RUSH))
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    session.elapsed_ms = 0.0
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

    assert session.elapsed_ms == 8000.0
    assert mode._spawn_state.spawn_cooldown_ms == 500.0
    assert mode.creatures.kill_count == 42


def test_quest_apply_resync_snapshot_restores_authoritative_runtime(make_mode_config) -> None:
    mode = _quest_mode(config=make_mode_config(game_mode=GameMode.QUESTS))
    mode.apply_terrain_setup = lambda **_kwargs: None  # type: ignore[method-assign]
    mode.start_run(QuestLevel(1, 1), status=None)
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    mode._quest_spawn_state.spawn_entries = ()
    mode._quest_spawn_state.spawn_timeline_ms = 0.0
    mode._quest_spawn_state.no_creatures_timer_ms = 0.0
    mode._quest_spawn_state.completion_transition_ms = -1.0
    session.elapsed_ms = 0.0

    spawn_entries = (
        SpawnEntry(
            pos=Vec2(64.0, 96.0),
            heading=45.0,
            spawn_id=SpawnId.ALIEN_RANDOM_06,
            trigger_ms=500,
            count=4,
        ),
    )
    snapshot = QuestsStateSnapshotV2(
        tick_index=55,
        runtime_state=QuestsRuntimeSnapshotV2(
            elapsed_ms=7000.0,
            spawn_entries=spawn_entries,
            spawn_timeline_ms=6500.0,
            no_creatures_timer_ms=250.0,
            completion_transition_ms=125.0,
            perk_pending_count=1,
        ),
    )

    mode._apply_resync_snapshot(snapshot)

    assert mode._quest_spawn_state.spawn_entries == spawn_entries
    assert mode._quest_spawn_state.spawn_timeline_ms == 6500.0
    assert mode._quest_spawn_state.no_creatures_timer_ms == 250.0
    assert mode._quest_spawn_state.completion_transition_ms == 125.0
    assert session.elapsed_ms == 7000.0


def test_consume_net_runtime_recovery_applies_snapshot_and_resets_runner(make_mode_config) -> None:
    mode = _survival_mode(config=make_mode_config(game_mode=GameMode.SURVIVAL))

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
    session.elapsed_ms = 0.0
    input_provider = LocalInputProvider(player_count=1, runtime=StaticLocalInputRuntime())
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

    assert session.elapsed_ms == 3000.0
    assert mode._spawn_state.stage == 2
    assert mode._spawn_state.spawn_cooldown_ms == 600.0
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


def test_quest_consume_net_runtime_recovery_restores_authoritative_runtime(make_mode_config) -> None:
    mode = _quest_mode(config=make_mode_config(game_mode=GameMode.QUESTS))
    mode.apply_terrain_setup = lambda **_kwargs: None  # type: ignore[method-assign]
    mode.start_run(QuestLevel(1, 1), status=None)
    mode._quest_spawn_state.spawn_entries = ()
    mode._quest_spawn_state.spawn_timeline_ms = 0.0
    mode._quest_spawn_state.no_creatures_timer_ms = 0.0
    mode._quest_spawn_state.completion_transition_ms = -1.0

    spawn_entries = (
        SpawnEntry(
            pos=Vec2(12.0, 34.0),
            heading=180.0,
            spawn_id=SpawnId.SPIDER_SP1_RANDOM_03,
            trigger_ms=800,
            count=1,
        ),
    )
    snapshot = QuestsStateSnapshotV2(
        tick_index=9,
        runtime_state=QuestsRuntimeSnapshotV2(
            elapsed_ms=4000.0,
            spawn_entries=spawn_entries,
            spawn_timeline_ms=3333.0,
            no_creatures_timer_ms=1200.0,
            completion_transition_ms=640.0,
            perk_pending_count=0,
        ),
    )
    payload = encode_mode_snapshot(snapshot=snapshot)
    mode._rollback_runtime = cast("RollbackRuntime", _RollbackRuntimeStub(tick_index=9, payload=payload))
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    input_provider = LocalInputProvider(player_count=1, runtime=StaticLocalInputRuntime())
    mode._tick_input_provider = input_provider
    mode._tick_runner = TickRunner(
        session=session,
        input_provider=input_provider,
        config=TickRunnerConfig(),
    )
    mode._tick_runner_session = session
    mode._tick_runner_is_networked = True
    mode._tick_runner_network_role = "client"
    mode._tick_runner_frame_index = 5
    mode._tick_runner_next_tick_index = 77
    mode._tick_runner_local_clock = FixedStepClock(tick_rate=60)

    mode._consume_net_runtime_recovery(mode_name="quests")

    assert mode._quest_spawn_state.spawn_entries == spawn_entries
    assert mode._quest_spawn_state.spawn_timeline_ms == 3333.0
    assert mode._quest_spawn_state.no_creatures_timer_ms == 1200.0
    assert mode._quest_spawn_state.completion_transition_ms == 640.0
    assert session.elapsed_ms == 4000.0
    runtime = mode._rollback_runtime
    assert isinstance(runtime, _RollbackRuntimeStub)
    assert runtime.marked_resync_ticks == [9]
    assert mode._tick_input_provider is None
    assert mode._tick_runner is None
    assert mode._tick_runner_session is None
    assert mode._tick_runner_is_networked is False
    assert mode._tick_runner_network_role == ""
    assert mode._tick_runner_frame_index == 0
    assert mode._tick_runner_next_tick_index == 0
    assert mode._tick_runner_local_clock is None
