from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update


def test_demo_mode_does_not_apply_movement_deadzone() -> None:
    input_state = PlayerInput(move_x=0.1, move_y=0.0, aim_x=512.0, aim_y=512.0)

    normal = GameplayState()
    normal.demo_mode_active = False
    player_normal = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player_update(player_normal, input_state, dt=1.0, state=normal)
    assert player_normal.pos.x == 512.0
    assert player_normal.pos.y == 512.0

    demo = GameplayState()
    demo.demo_mode_active = True
    player_demo = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    player_update(player_demo, input_state, dt=1.0, state=demo)
    assert player_demo.pos.x > 512.0
