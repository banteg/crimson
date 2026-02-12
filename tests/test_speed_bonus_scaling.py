from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState


def test_speed_bonus_adds_one_to_speed_multiplier() -> None:
    dt = 0.1
    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0))
    move_heading = Vec2(1.0, 0.0).to_heading()

    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0, heading=move_heading)
    player_update(base_player, input_state, dt, base_state)
    assert base_player.pos.x == pytest.approx(110.0)

    boosted_state = GameplayState()
    boosted_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0, heading=move_heading)
    boosted_player.speed_bonus_timer = 1.0
    player_update(boosted_player, input_state, dt, boosted_state)
    assert boosted_player.pos.x == pytest.approx(115.0)
