from __future__ import annotations

from .math_parity import f32, x87_pc24_add, x87_pc24_mul

_NATIVE_FIND_SIZE_MARGIN_SCALE = f32(0.14285715)
_NATIVE_FIND_SIZE_MARGIN_BIAS = f32(3.0)


def native_find_size_margin(target_size: float) -> float:
    """Native collision threshold term used by `*_find_in_radius` routines."""

    return x87_pc24_add(
        x87_pc24_mul(f32(target_size), _NATIVE_FIND_SIZE_MARGIN_SCALE),
        _NATIVE_FIND_SIZE_MARGIN_BIAS,
    )


__all__ = ["native_find_size_margin"]
