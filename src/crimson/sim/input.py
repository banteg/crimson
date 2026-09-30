from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..aim_schemes import AimScheme
from ..movement_controls import MovementControlType


class PlayerInput(msgspec.Struct, frozen=True, kw_only=True):
    # The player's `config_movement_schemes` / `config_aim_schemes` entries, which `player_update` reads each frame.
    move_mode: MovementControlType
    aim_scheme: AimScheme
    move: Vec2 = Vec2()
    aim: Vec2 = Vec2()
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False
    reload_down: bool = False
    fire_bullets_key_down: bool = False
    # Held aim-turn controls: `aim_key_left/right` under keyboard aim, the POV hat under joystick aim.
    aim_turn_left: bool = False
    aim_turn_right: bool = False
    # Legacy names: these four fields carry held controls, not press edges.
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
