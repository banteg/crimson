from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2

from .creatures.lifecycle import creature_lifecycle_is_collidable
from .math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub

if TYPE_CHECKING:
    from .creatures.runtime import CreatureState

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


def creature_find_in_radius(creatures: Sequence[CreatureState], *, pos: Vec2, radius: float, start_index: int) -> int:
    """Port of `creature_find_in_radius` (0x004206a0): the first collidable creature touching the circle."""

    for idx in range(start_index, len(creatures)):
        creature = creatures[idx]
        if not creature.active:
            continue
        if not within_native_find_radius(origin=pos, target=creature.pos, radius=radius, target_size=creature.size):
            continue
        if not creature_lifecycle_is_collidable(creature.death_timer):
            continue
        return idx
    return -1


__all__ = ["creature_find_in_radius", "native_find_size_margin", "within_native_find_radius"]
