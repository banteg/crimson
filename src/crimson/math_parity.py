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


def _f32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]


# Native movement/heading code uses these exact float32 literals.
NATIVE_PI = _f32_from_bits(0x40490FDB)
NATIVE_HALF_PI = _f32_from_bits(0x3FC90FDB)
NATIVE_TAU = _f32_from_bits(0x40C90FDB)
NATIVE_TURN_RATE_SCALE = _f32_from_bits(0x3FAAAAAB)


def f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


_NATIVE_LEFT_AXIS_HEADING_POS = f32(NATIVE_TAU - NATIVE_HALF_PI)
_NATIVE_LEFT_AXIS_HEADING_EPS = 1e-6
_NATIVE_LEFT_AXIS_DY_EPS = 5e-4


def f32_vec2(value: Vec2) -> Vec2:
    return Vec2(f32(value.x), f32(value.y))


def sin_f32(radians: float) -> float:
    return f32(math.sin(float(radians)))


def cos_f32(radians: float) -> float:
    return f32(math.cos(float(radians)))


def atan2_f32(y: float, x: float) -> float:
    return f32(math.atan2(float(y), float(x)))


def heading_from_delta_f32(*, dx: float, dy: float) -> float:
    heading = f32(math.atan2(float(dy), float(dx)) + NATIVE_HALF_PI)
    # `fpatan` boundary case: native can encode left-axis headings as `-pi/2`
    # (instead of `3pi/2`) and that representation feeds branchy angle_approach
    # decisions. Treat near-axis, near-horizontal vectors as the negative branch
    # to match native tie-break behavior around signed-zero boundaries.
    if (
        float(dx) < 0.0
        and abs(float(heading) - float(_NATIVE_LEFT_AXIS_HEADING_POS)) <= _NATIVE_LEFT_AXIS_HEADING_EPS
        and abs(float(dy)) <= _NATIVE_LEFT_AXIS_DY_EPS
    ):
        return f32(float(heading) - NATIVE_TAU)
    return heading


def heading_add_pi_f32(heading: float) -> float:
    return f32(float(heading) + NATIVE_PI)


def heading_to_direction_f32(heading: float) -> Vec2:
    radians = float(f32(heading)) - NATIVE_HALF_PI
    return Vec2(cos_f32(radians), sin_f32(radians))
