from __future__ import annotations

import pytest

from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.session_builders import build_survival_session
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import step_player
from tests.support.helpers import assert_float_close


def _player_roundtrip_dt(dt: float, *, reflex_boost: float) -> float:
    """frame_dt as `player_update` leaves it for the rest of the frame under Reflex Boost."""

    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2())
    world.players.append(player)
    world.state.time_scale_active = True
    world.state.bonuses.reflex_boost = reflex_boost
    return step_player(world, player, PlayerInput(), dt)


def test_reflex_boosted_perk_dt_step_scales_world_step_by_0_9() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2())
    player.move_speed = 2.0
    player.heading = Vec2(1.0, 0.0).to_heading()
    world.state.perks[int(PerkId.REFLEX_BOOSTED)] = 1
    world.players.append(player)

    # The session applies the perk dt steps before stepping the world.
    world.step(
        world.world_dt_after_perk_steps(1.0),
        inputs=[PlayerInput(move=Vec2(1.0, 0.0))],
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        mid_step_runtime=None,
        violence_disabled=0,
        game_tune_started=False,
        perk_progression_enabled=False,
    )

    # 100.0 * 0.9 (speed_multiplier=2.0, move_speed=2.0), up to the PC24 velocity chain.
    assert player.pos.x == pytest.approx(90.0, abs=1e-4)


def test_survival_session_shares_reflex_boosted_dt_with_mode_timers() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2())
    world.state.perks[int(PerkId.REFLEX_BOOSTED)] = 1
    world.players.append(player)
    session, spawn = build_survival_session(
        world=world,
        detail_preset=5,
        violence_disabled=0,
    )
    spawn.spawn_cooldown_ms = 1000.0

    tick = session.step_tick(dt=0.1, inputs=[PlayerInput()])

    assert tick.timing.dt_ms_i32 == 100
    # 0.1f * 0.9f stores 0.089999996f, whose native x87 * 1000 +
    # truncation path produces 89 ms.
    assert tick.timing.dt_sim_ms_i32 == 89
    assert tick.elapsed_ms == 89.0
    assert spawn.spawn_cooldown_ms == 911.0


def test_world_step_uses_player_roundtrip_dt_for_post_player_bonus_timers() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2()))
    world.state.time_scale_active = True
    # Use a near-expiry timer value where the player_update roundtrip path
    # produces a distinct float32 decrement from plain `dt`.
    world.state.bonuses.reflex_boost = 0.05

    dt = 0.0109
    expected_post_player_dt = _player_roundtrip_dt(dt, reflex_boost=world.state.bonuses.reflex_boost)
    expected_reflex = float(f32(float(world.state.bonuses.reflex_boost) - float(expected_post_player_dt)))

    world.step(
        dt,
        inputs=[PlayerInput()],
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        mid_step_runtime=None,
        violence_disabled=0,
        game_tune_started=False,
        perk_progression_enabled=False,
    )

    assert_float_close(world.state.bonuses.reflex_boost, expected_reflex)


def test_player_time_scale_roundtrip_restores_scaled_dt() -> None:
    dt_sim = f32(f32(0.09) * f32(0.3))

    assert _player_roundtrip_dt(dt_sim, reflex_boost=f32(3.0)) == dt_sim


def test_session_does_not_apply_player_time_scale_twice() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.players.append(PlayerState(index=0, pos=Vec2()))
    world.state.time_scale_active = True
    world.state.bonuses.reflex_boost = f32(3.0)
    session, _spawn = build_survival_session(
        world=world,
        detail_preset=5,
        violence_disabled=0,
    )

    dt_sim = f32(f32(0.09) * f32(0.3))
    post_player_dt = _player_roundtrip_dt(dt_sim, reflex_boost=world.state.bonuses.reflex_boost)
    expected_reflex = f32(f32(3.0) - post_player_dt)

    session.step_tick(dt=0.09, inputs=[PlayerInput()])

    assert world.state.bonuses.reflex_boost == expected_reflex
