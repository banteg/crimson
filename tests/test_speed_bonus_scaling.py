from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update


def test_speed_bonus_adds_one_to_speed_multiplier() -> None:
    dt = 0.1
    input_state = PlayerInput(move_x=1.0, move_y=0.0, aim=Vec2(101.0, 100.0))

    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0)
    player_update(base_player, input_state, dt, base_state)
    assert base_player.pos.x == pytest.approx(110.0)

    boosted_state = GameplayState()
    boosted_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0)
    boosted_player.speed_bonus_timer = 1.0
    player_update(boosted_player, input_state, dt, boosted_state)
    assert boosted_player.pos.x == pytest.approx(115.0)
