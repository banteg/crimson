from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..aim_schemes import AimScheme
from ..movement_controls import MovementControlType


class PlayerInput(msgspec.Struct, frozen=True, kw_only=True):
    # The player's `config_movement_schemes` / `config_aim_schemes` entries, which `player_update` reads each frame.
    move_mode: MovementControlType
    aim_scheme: AimScheme
    # The dual action pad's move stick, or the point-click move target (x = -1 when unset).
    move: Vec2 = Vec2()
    # The world aim point; the screen cursor under relative mouse aim; the reach from the player
    # under dual action pad aim.
    aim: Vec2 = Vec2()
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False
    reload_down: bool = False
    fire_bullets_key_down: bool = False
    # Held aim-turn controls: `aim_key_left/right` under keyboard aim, the POV hat under joystick aim.
    aim_turn_left: bool = False
    aim_turn_right: bool = False
    # Held movement keys (`move_key_forward/backward`, `turn_key_left/right`, or the single-player
    # arrow alternates); legacy names, they carry held controls, not press edges.
    move_forward_down: bool
    move_backward_down: bool
    turn_left_down: bool
    turn_right_down: bool
