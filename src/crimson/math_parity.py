from __future__ import annotations

"""Float/trig helpers for native movement math parity."""

import math
import struct

from grim.geom import Vec2

__all__ = [
    "NATIVE_HALF_PI",
    "NATIVE_PI",
    "NATIVE_TAU",
    "NATIVE_TURN_RATE_SCALE",
    "atan2_f32",
    "f32",
    "f32_vec2",
    "heading_add_pi_f32",
    "heading_from_delta_f32",
    "heading_to_direction_f32",
]

# Native movement/heading code uses these float literals.
NATIVE_PI = 3.1415927
NATIVE_HALF_PI = 1.5707964
NATIVE_TAU = 6.2831855
NATIVE_TURN_RATE_SCALE = 1.3333334


def f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def f32_vec2(value: Vec2) -> Vec2:
    return Vec2(f32(value.x), f32(value.y))


def sin_f32(radians: float) -> float:
    return f32(math.sin(float(radians)))


def cos_f32(radians: float) -> float:
    return f32(math.cos(float(radians)))


def atan2_f32(y: float, x: float) -> float:
    return f32(math.atan2(float(y), float(x)))


def heading_from_delta_f32(*, dx: float, dy: float) -> float:
    return f32(atan2_f32(dy, dx) + NATIVE_HALF_PI)


def heading_add_pi_f32(heading: float) -> float:
    return f32(f32(heading) + NATIVE_PI)


def heading_to_direction_f32(heading: float) -> Vec2:
    radians = f32(f32(heading) - NATIVE_HALF_PI)
    return Vec2(cos_f32(radians), sin_f32(radians))
