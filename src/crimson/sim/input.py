from __future__ import annotations

from dataclasses import dataclass, field

from grim.geom import Vec2


@dataclass(frozen=True, slots=True)
class PlayerInput:
    move: Vec2 = field(default_factory=Vec2)
    aim: Vec2 = field(default_factory=Vec2)
    fire_down: bool = False
    fire_pressed: bool = False
    reload_pressed: bool = False
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
