from __future__ import annotations

from grim.geom import Vec2

from .math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub

_NATIVE_FIND_SIZE_MARGIN_SCALE = f32(0.14285715)
_NATIVE_FIND_SIZE_MARGIN_BIAS = f32(3.0)


def native_find_size_margin(target_size: float) -> float:
    """Native collision threshold term used by `*_find_in_radius` routines."""

    return x87_pc24_add(
        x87_pc24_mul(f32(target_size), _NATIVE_FIND_SIZE_MARGIN_SCALE),
        _NATIVE_FIND_SIZE_MARGIN_BIAS,
    )


def within_native_find_radius(*, origin: Vec2, target: Vec2, radius: float, target_size: float) -> bool:
    """Evaluate the native strict ``*_find_in_radius`` predicate."""

    dx = x87_pc24_sub(f32(target.x), f32(origin.x))
    dy = x87_pc24_sub(f32(target.y), f32(origin.y))
    distance = x87_pc24_hypot(dx, dy)
    distance_outside_radius = x87_pc24_sub(distance, f32(radius))
    return distance_outside_radius < native_find_size_margin(float(target_size))


__all__ = ["native_find_size_margin", "within_native_find_radius"]
