from __future__ import annotations

from pathlib import Path

from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import QuestDeterministicSession
from grim.geom import Vec2
from tests.world_runtime import WorldRuntimeHost


def _build_session(*, seed: int = 101, level: str = "1.1") -> QuestDeterministicSession:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(seed), player_count=1)
    quest = quest_by_level(level)
    assert quest is not None
    entries = tuple(
        build_quest_spawn_table(
            quest,
            QuestContext(width=1024, height=1024, player_count=1),
            seed=int(seed),
            hardcore=False,
            full_version=True,
        ),
    )
    return QuestDeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        fx_queue=world.render_resources.fx_queue,
        fx_queue_rotated=world.render_resources.fx_queue_rotated,
        spawn_entries=entries,
    )


def test_quest_session_tick_exposes_required_fields() -> None:
    session = _build_session(seed=101)
    timing = session.timing_for_dt(1.0 / 60.0)
    tick = session.step_tick(
        timing=timing,
        inputs=[PlayerInput(aim=Vec2(512.0, 512.0))],
    )

    assert tick.step.command_hash
    assert isinstance(tick.elapsed_ms, float)
    assert isinstance(tick.rng_marks, dict)
    assert isinstance(tick.creature_count_world_step, int)
    assert isinstance(tick.spawn_timeline_ms, float)
    assert isinstance(tick.no_creatures_timer_ms, float)
    assert isinstance(tick.completion_transition_ms, float)
    assert isinstance(tick.completed, bool)
    assert isinstance(tick.play_hit_sfx, bool)
    assert isinstance(tick.play_completion_music, bool)


def test_quest_session_is_deterministic_for_same_seed_and_inputs() -> None:
    session0 = _build_session(seed=101)
    session1 = _build_session(seed=101)
    inputs = [PlayerInput(aim=Vec2(512.0, 512.0))]

    trace0: list[tuple[str, int, float, float, float]] = []
    trace1: list[tuple[str, int, float, float, float]] = []

    for _ in range(8):
        tick0 = session0.step_tick(timing=session0.timing_for_dt(1.0 / 60.0), inputs=inputs)
        trace0.append(
            (
                str(tick0.step.command_hash),
                int(tick0.rng_marks.get("after_world_step", -1)),
                float(tick0.spawn_timeline_ms),
                float(tick0.no_creatures_timer_ms),
                float(tick0.completion_transition_ms),
            ),
        )

        tick1 = session1.step_tick(timing=session1.timing_for_dt(1.0 / 60.0), inputs=inputs)
        trace1.append(
            (
                str(tick1.step.command_hash),
                int(tick1.rng_marks.get("after_world_step", -1)),
                float(tick1.spawn_timeline_ms),
                float(tick1.no_creatures_timer_ms),
                float(tick1.completion_transition_ms),
            ),
        )

    assert trace0 == trace1


def test_quest_session_clears_reflex_boost_when_quest_is_idle_complete() -> None:
    session = _build_session(seed=101)
    session.spawn_entries = ()
    session.world.state.bonuses.reflex_boost = 0.25471345
    session.world.state.time_scale_active = True

    timing = session.timing_for_dt(0.054)
    tick = session.step_tick(
        timing=timing,
        inputs=[PlayerInput()],
    )

    assert tick.spawn_timeline_ms == 0.0
    assert session.world.state.bonuses.reflex_boost == 0.0
    assert session.world.state.time_scale_active is False


def test_quest_timing_does_not_zero_dt_for_pending_perk_prompt() -> None:
    session = _build_session(seed=101)
    session.world.state.perk_selection.pending_count = 1

    timing = session.timing_for_dt(1.0 / 60.0)

    assert timing.zero_gate_active is False
    assert timing.dt_sim > 0.0
