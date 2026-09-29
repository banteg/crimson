from __future__ import annotations

import struct

# Reuse bound struct methods in the float32 hot path.
_F32_STRUCT = struct.Struct("<f")
_F32_PACK = _F32_STRUCT.pack
_F32_UNPACK = _F32_STRUCT.unpack


def f32(value: float) -> float:
    """Round a double to the float32 the game stores."""
    return _F32_UNPACK(_F32_PACK(float(value)))[0]


def f32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]


def f32_bits_i32(value: float) -> int:
    """Reinterpret a float32 as its signed int32 bit pattern (a float/int union read)."""
    return struct.unpack("<i", struct.pack("<f", float(value)))[0]


def i32(value: int) -> int:
    """Wrap to a signed 32-bit int, the low 32 bits a register holds."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def clamp(value: float, low: float, high: float) -> float:
    if value < low:
        return low
    if value > high:
        return high
    return value


def clamp01(value: float) -> float:
    return clamp(value, 0.0, 1.0)


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t
