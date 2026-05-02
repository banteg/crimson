from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import DeterministicSession, QuestSessionRuntime, QuestSpawnState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.world_runtime import WorldRuntimeHost


def _build_session(*, seed: int = 101, level: str = "1.1") -> tuple[DeterministicSession, QuestSpawnState]:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(seed), player_count=1)
    quest = quest_by_level(QuestLevel.parse(level))
    assert quest is not None
    entries = tuple(
        build_quest_spawn_table(
            quest,
            QuestContext(width=1024, height=1024, player_count=1),
            rng=Crand(int(seed)),
            hardcore=False,
            full_version=True,
        ),
    )
    spawn_state = QuestSpawnState(spawn_entries=entries)
    session = DeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        game_mode=GameMode.QUESTS,
        perk_progression_enabled=True,
        mode_runtime=QuestSessionRuntime(spawn=spawn_state),
    )
    return session, spawn_state

def test_quest_session_tick_exposes_required_fields() -> None:
    session, spawn_state = _build_session(seed=101)
    tick = session.step_tick(
        dt=1.0 / 60.0,
        inputs=[PlayerInput(aim=Vec2(512.0, 512.0))],
    )

    assert tick.step is not None
    assert isinstance(tick.elapsed_ms, float)
    assert isinstance(tick.creature_count_world_step, int)
    assert not hasattr(tick, "spawn_timeline_ms")
    assert not hasattr(tick, "no_creatures_timer_ms")
    assert not hasattr(tick, "completion_transition_ms")
    assert not hasattr(tick, "completed")
    assert not hasattr(tick, "play_hit_sfx")
    assert not hasattr(tick, "play_completion_music")
    assert isinstance(spawn_state.spawn_timeline_ms, float)
    assert isinstance(spawn_state.no_creatures_timer_ms, float)
    assert isinstance(spawn_state.completion_transition_ms, float)
    assert isinstance(spawn_state.completed, bool)
    assert isinstance(spawn_state.play_hit_sfx, bool)
    assert isinstance(spawn_state.play_completion_music, bool)

def test_quest_session_is_deterministic_for_same_seed_and_inputs() -> None:
    session0, spawn0 = _build_session(seed=101)
    session1, spawn1 = _build_session(seed=101)
    inputs = [PlayerInput(aim=Vec2(512.0, 512.0))]

    trace0: list[tuple[float, int, float, float, float]] = []
    trace1: list[tuple[float, int, float, float, float]] = []

    for _ in range(8):
        tick0 = session0.step_tick(dt=1.0 / 60.0, inputs=inputs)
        trace0.append(
            (
                float(tick0.step.dt_sim),
                int(session0.world.state.rng.state),
                float(spawn0.spawn_timeline_ms),
                float(spawn0.no_creatures_timer_ms),
                float(spawn0.completion_transition_ms),
            ),
        )

        tick1 = session1.step_tick(dt=1.0 / 60.0, inputs=inputs)
        trace1.append(
            (
                float(tick1.step.dt_sim),
                int(session1.world.state.rng.state),
                float(spawn1.spawn_timeline_ms),
                float(spawn1.no_creatures_timer_ms),
                float(spawn1.completion_transition_ms),
            ),
        )

    assert trace0 == trace1

def test_quest_session_clears_reflex_boost_when_quest_is_idle_complete() -> None:
    session, spawn_state = _build_session(seed=101)
    spawn_state.spawn_entries = ()
    session.world.state.bonuses.reflex_boost = 0.25471345
    session.world.state.time_scale_active = True

    _tick = session.step_tick(
        dt=0.054,
        inputs=[PlayerInput()],
    )

    assert spawn_state.spawn_timeline_ms == 0.0
    assert session.world.state.bonuses.reflex_boost == 0.0
    assert session.world.state.time_scale_active is False

def test_quest_timing_does_not_zero_dt_for_pending_perk_prompt() -> None:
    session, _spawn_state = _build_session(seed=101)
    session.world.state.perk_selection.pending_count = 1

    timing = session.timing_for_dt(1.0 / 60.0)

    assert timing.zero_gate_active is False
    assert timing.dt_sim > 0.0
