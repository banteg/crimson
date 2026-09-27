from __future__ import annotations

from crimson.movement_controls import MovementControlType
from crimson.sim.input import PlayerInput
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_player


def test_computer_move_mode_does_not_apply_movement_deadzone() -> None:
    small_move = Vec2(0.1, 0.0)
    aim = Vec2(512.0, 512.0)

    pad = make_world()
    player_pad = pad.players[0]
    player_pad.pos = Vec2(512.0, 512.0)
    step_player(pad, player_pad, PlayerInput(move=small_move, aim=aim), dt=1.0)
    assert player_pad.pos.x == 512.0
    assert player_pad.pos.y == 512.0

    computer = make_world()
    player_computer = computer.players[0]
    player_computer.pos = Vec2(512.0, 512.0)
    step_player(
        computer,
        player_computer,
        PlayerInput(move=small_move, aim=aim, move_mode=MovementControlType.COMPUTER),
        dt=1.0,
    )
    assert player_computer.pos.x > 512.0
