from __future__ import annotations

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_long_distance_runner_ramps_speed_above_base_cap() -> None:
    dt = 0.1
    steps = 12  # reaches move_speed cap (2.8)

    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0))

    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    for _ in range(steps):
        player_update(base_player, input_state, dt, base_state)

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    perk_player.perk_counts[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    for _ in range(steps):
        player_update(perk_player, input_state, dt, perk_state)

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
    player_update(perk_player, PlayerInput(aim=Vec2(perk_player.pos.x + 1.0, perk_player.pos.y)), dt, perk_state)
    expected_coast_speed = float(f32(float(expected_perk_speed) - dt_f32 * 15.0))
    assert_float_close(perk_player.move_speed, expected_coast_speed)
    assert perk_player.pos.x > prev_x


def test_preserve_mode_uses_player_zero_long_distance_runner_for_player_one() -> None:
    state = GameplayState(preserve_bugs=True)
    player0 = PlayerState(index=0, pos=Vec2())
    player0.perk_counts[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    player1 = PlayerState(index=1, pos=Vec2(), move_speed=2.1)

    player_update(
        player1,
        PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(1.0, 0.0)),
        0.1,
        state,
        players=[player0, player1],
    )

    assert_float_close(player1.move_speed, f32(2.2))
