from __future__ import annotations

import pyray as rl
from raylib import defines as rd
from raylib import ffi

__all__ = ["rd", "rl", "rl_color", "rl_rectangle", "rl_vector2"]


# These value types contain no pointers. CFFI owns their allocation directly;
# pyray's generic constructor/buffer-retention machinery is unnecessary here.
def rl_color(r: int, g: int, b: int, a: int) -> rl.Color:
    return ffi.new("Color *", (r, g, b, a))[0]


def rl_rectangle(x: float, y: float, width: float, height: float) -> rl.Rectangle:
    return ffi.new("Rectangle *", (x, y, width, height))[0]


def rl_vector2(x: float, y: float) -> rl.Vector2:
    return ffi.new("Vector2 *", (x, y))[0]
