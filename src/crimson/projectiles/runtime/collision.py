from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2

from ...collision_math import native_find_size_margin
from ...creatures.lifecycle import creature_lifecycle_is_alive
from ...math_parity import f32, x87_pc24_hypot, x87_pc24_sub

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState

def creature_find_nearest_alive(
    *,
    creatures: Sequence[CreatureState],
    origin: Vec2,
    preserve_bugs: bool = False,
) -> int:
    """Port of `creature_find_nearest(origin, -1, 0.0)`."""

    best_idx = 0 if preserve_bugs else -1
    best_distance = f32(1_000_000.0)
    max_index = min(len(creatures), 0x180)
    for idx in range(max_index):
        creature = creatures[idx]
        if not creature.active:
            continue
        if not creature_lifecycle_is_alive(creature.lifecycle_stage):
            continue
        dx = x87_pc24_sub(f32(origin.x), f32(creature.pos.x))
        dy = x87_pc24_sub(f32(origin.y), f32(creature.pos.y))
        distance = x87_pc24_hypot(dx, dy)
        if distance < best_distance:
            best_distance = distance
            best_idx = idx
    return best_idx


def creature_find_nearest_active(
    *,
    creatures: Sequence[CreatureState],
    origin: Vec2,
    exclude_id: int,
    min_dist: float,
    preserve_bugs: bool = False,
) -> int:
    """Port of ``creature_find_nearest(origin, exclude_id, min_dist)``.

    This native branch accepts every active creature, regardless of lifecycle,
    and compares the stored PC=24 square-root distance against both bounds.
    """

    best_idx = 0 if preserve_bugs else -1
    best_distance = f32(1_000_000.0)
    minimum_distance = f32(min_dist)
    max_index = min(len(creatures), 0x180)
    for idx in range(max_index):
        creature = creatures[idx]
        if not creature.active or idx == int(exclude_id):
            continue
        dx = x87_pc24_sub(f32(origin.x), f32(creature.pos.x))
        dy = x87_pc24_sub(f32(origin.y), f32(creature.pos.y))
        distance = x87_pc24_hypot(dx, dy)
        if distance > minimum_distance and distance < best_distance:
            best_distance = distance
            best_idx = idx
    return best_idx


__all__ = [
    "creature_find_nearest_active",
    "creature_find_nearest_alive",
    "native_find_size_margin",
]
