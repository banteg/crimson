from __future__ import annotations

import msgspec

from grim.geom import Vec2

from ..aim_schemes import AimScheme
from ..movement_controls import MovementControlType


class PlayerInput(msgspec.Struct, frozen=True):
    move: Vec2 = Vec2()
    aim: Vec2 = Vec2()
    move_mode: MovementControlType | None = None
    aim_scheme: AimScheme | None = None
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False
    reload_down: bool = False
    move_to_cursor_pressed: bool = False
    # Legacy names: these four fields carry held controls, not press edges.
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
