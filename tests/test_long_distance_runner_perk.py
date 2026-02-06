from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update
from crimson.perks import PerkId


def test_long_distance_runner_ramps_speed_above_base_cap() -> None:
    dt = 0.1
    steps = 12  # reaches move_speed cap (2.8)

    input_state = PlayerInput(move_x=1.0, move_y=0.0, aim_x=101.0, aim_y=100.0)

    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    for _ in range(steps):
        player_update(base_player, input_state, dt, base_state)

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    perk_player.perk_counts[int(PerkId.LONG_DISTANCE_RUNNER)] = 1
    for _ in range(steps):
        player_update(perk_player, input_state, dt, perk_state)

    assert base_player.move_speed == pytest.approx(2.0)
    assert perk_player.move_speed == pytest.approx(2.8)
    assert perk_player.pos.x > base_player.pos.x

    # With no movement input, the player coasts while decelerating.
    prev_x = perk_player.pos.x
    player_update(perk_player, PlayerInput(aim_x=perk_player.pos.x + 1.0, aim_y=perk_player.pos.y), dt, perk_state)
    assert perk_player.move_speed == pytest.approx(1.3)  # 2.8 - (dt * 15.0)
    assert perk_player.pos.x > prev_x
