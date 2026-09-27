from __future__ import annotations

from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_player


def test_demo_mode_does_not_apply_movement_deadzone() -> None:
    input_state = PlayerInput(move=Vec2(0.1, 0.0), aim=Vec2(512.0, 512.0))

    normal = make_world()
    normal.state.demo_mode_active = False
    player_normal = normal.players[0]
    player_normal.pos = Vec2(512.0, 512.0)
    step_player(normal, player_normal, input_state, dt=1.0)
    assert player_normal.pos.x == 512.0
    assert player_normal.pos.y == 512.0

    demo = make_world()
    demo.state.demo_mode_active = True
    player_demo = demo.players[0]
    player_demo.pos = Vec2(512.0, 512.0)
    step_player(demo, player_demo, input_state, dt=1.0)
    assert player_demo.pos.x > 512.0
