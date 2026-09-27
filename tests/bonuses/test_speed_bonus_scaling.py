from __future__ import annotations

from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_player
from tests.support.helpers import assert_float_close


def test_speed_bonus_adds_one_to_speed_multiplier() -> None:
    dt = 0.1
    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0))
    move_heading = Vec2(1.0, 0.0).to_heading()

    base_world = make_world()
    base_player = base_world.players[0]
    base_player.pos = Vec2(100.0, 100.0)
    base_player.move_speed = 2.0
    base_player.heading = move_heading
    step_player(base_world, base_player, input_state, dt)
    assert_float_close(base_player.pos.x, 110.0)

    boosted_world = make_world()
    boosted_player = boosted_world.players[0]
    boosted_player.pos = Vec2(100.0, 100.0)
    boosted_player.move_speed = 2.0
    boosted_player.heading = move_heading
    boosted_player.speed_bonus_timer = 1.0
    step_player(boosted_world, boosted_player, input_state, dt)
    assert_float_close(boosted_player.pos.x, 115.0)
