from __future__ import annotations

"""Float/trig helpers for native movement math parity."""

import math
import struct

from grim.geom import Vec2

__all__ = [
    "NATIVE_HALF_PI",
    "NATIVE_PI",
    "NATIVE_QUARTER_PI",
    "NATIVE_TAU",
    "NATIVE_TURN_RATE_SCALE",
    "atan2_f32",
    "f32",
    "f32_vec2",
    "heading_add_pi_f32",
    "heading_from_delta_f32",
    "heading_to_direction_f32",
    "x87_pc24_add",
    "x87_fpatan",
    "x87_pc24_cos_mul",
    "x87_pc24_div",
    "x87_pc24_hypot",
    "x87_pc24_mul",
    "x87_pc24_mul_chain",
    "x87_pc24_sqrt",
    "x87_pc24_sin_mul",
    "x87_pc24_sub",
]


def _f32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]


# Reuse bound struct methods in the float32 hot path.
_F32_STRUCT = struct.Struct("<f")
_F32_PACK = _F32_STRUCT.pack
_F32_UNPACK = _F32_STRUCT.unpack


# Native movement/heading code uses these exact float32 literals.
NATIVE_PI = _f32_from_bits(0x40490FDB)
NATIVE_HALF_PI = _f32_from_bits(0x3FC90FDB)
NATIVE_QUARTER_PI = _f32_from_bits(0x3F490FDB)
NATIVE_TAU = _f32_from_bits(0x40C90FDB)
NATIVE_TURN_RATE_SCALE = _f32_from_bits(0x3FAAAAAB)


def f32(value: float) -> float:
    return _F32_UNPACK(_F32_PACK(float(value)))[0]


def x87_pc24_add(lhs: float, rhs: float) -> float:
    """Add using the game's x87 24-bit significand precision."""

    return f32(float(lhs) + float(rhs))


def x87_fpatan(y: float, x: float) -> float:
    """Evaluate ``fpatan`` while keeping its result wide for follow-up math."""

    return math.atan2(float(y), float(x))


def x87_pc24_sub(lhs: float, rhs: float) -> float:
    """Subtract using the game's x87 24-bit significand precision."""

    return f32(float(lhs) - float(rhs))


def x87_pc24_div(lhs: float, rhs: float) -> float:
    """Divide using the game's x87 24-bit significand precision."""

    return f32(float(lhs) / float(rhs))


def x87_pc24_mul(lhs: float, rhs: float) -> float:
    """Multiply using the game's x87 24-bit significand precision."""

    return f32(float(lhs) * float(rhs))


def x87_pc24_sqrt(value: float) -> float:
    """Square-root using the game's x87 24-bit significand precision."""

    return f32(math.sqrt(float(value)))


def x87_pc24_hypot(x: float, y: float) -> float:
    """Evaluate ``sqrt(x*x + y*y)`` with PC=24 rounding per operation."""

    return x87_pc24_sqrt(
        x87_pc24_add(
            x87_pc24_mul(x, x),
            x87_pc24_mul(y, y),
        ),
    )


def x87_pc24_mul_chain(first: float, *factors: float) -> float:
    """Multiply left-to-right, rounding after every x87 PC=24 operation."""

    result = float(first)
    for factor in factors:
        result = x87_pc24_mul(result, factor)
    return result


def x87_pc24_cos_mul(radians: float, *factors: float) -> float:
    """Evaluate cosine wide, then multiply with PC=24 rounding."""

    return x87_pc24_mul_chain(math.cos(float(radians)), *factors)


def x87_pc24_sin_mul(radians: float, *factors: float) -> float:
    """Evaluate sine wide, then multiply with PC=24 rounding."""

    return x87_pc24_mul_chain(math.sin(float(radians)), *factors)


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
    radians = f32(float(f32(heading)) - NATIVE_HALF_PI)
    return Vec2(cos_f32(radians), sin_f32(radians))
