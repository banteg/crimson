from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_player
from tests.support.helpers import assert_float_close


def test_long_distance_runner_ramps_speed_above_base_cap() -> None:
    dt = 0.1
    steps = 12  # reaches move_speed cap (2.8)

    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0))

    base_world = make_world()
    base_player = base_world.players[0]
    base_player.pos = Vec2(100.0, 100.0)
    for _ in range(steps):
        step_player(base_world, base_player, input_state, dt)

    perk_world = make_world()
    perk_player = perk_world.players[0]
    perk_player.pos = Vec2(100.0, 100.0)
    perk_world.state.perks[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    for _ in range(steps):
        step_player(perk_world, perk_player, input_state, dt)

    expected_perk_speed = 0.0
    dt_f32 = float(f32(dt))
    for _ in range(steps):
        if expected_perk_speed < 2.0:
            expected_perk_speed = float(f32(float(expected_perk_speed) + dt_f32 * 4.0))
        expected_perk_speed = float(f32(float(expected_perk_speed) + dt_f32))
        if expected_perk_speed > 2.8:
            expected_perk_speed = 2.8

    assert_float_close(base_player.move_speed, 2.0)
    assert_float_close(perk_player.move_speed, expected_perk_speed)
    assert perk_player.pos.x > base_player.pos.x

    # With no movement input, the player coasts while decelerating.
    prev_x = perk_player.pos.x
    step_player(perk_world, perk_player, PlayerInput(aim=Vec2(perk_player.pos.x + 1.0, perk_player.pos.y)), dt)
    expected_coast_speed = float(f32(float(expected_perk_speed) - dt_f32 * 15.0))
    assert_float_close(perk_player.move_speed, expected_coast_speed)
    assert perk_player.pos.x > prev_x
