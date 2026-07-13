from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2

from ...collision_math import native_find_size_margin
from ...creatures.damage_runtime import CreatureDamageRuntime
from ...creatures.lifecycle import creature_lifecycle_is_alive
from ...math_parity import f32, x87_pc24_hypot, x87_pc24_sub
from ...owner_ref import OwnerRef

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState

def _hit_radius_for(creature: CreatureState) -> float:
    """Return the native size term used by the radius predicates.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    return native_find_size_margin(float(creature.size))


def _within_native_find_radius(*, origin: Vec2, target: Vec2, radius: float, target_size: float) -> bool:
    """Mirror native `creature_find_in_radius` / `player_find_in_radius` predicate.

    Native uses:
      sqrt(dx*dx + dy*dy) - radius < size * 0.14285715 + 3.0
    """

    dx = x87_pc24_sub(f32(target.x), f32(origin.x))
    dy = x87_pc24_sub(f32(target.y), f32(origin.y))
    distance = x87_pc24_hypot(dx, dy)
    distance_outside_radius = x87_pc24_sub(distance, f32(radius))
    size_margin = native_find_size_margin(float(target_size))
    return distance_outside_radius < size_margin


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


def _apply_damage_to_creature(
    creatures: Sequence[CreatureState],
    creature_index: int,
    damage: float,
    *,
    damage_type: int,
    impulse: Vec2,
    owner: OwnerRef,
    creature_damage_runtime: CreatureDamageRuntime,
) -> None:
    if damage <= 0.0:
        return
    idx = int(creature_index)
    if not (0 <= idx < len(creatures)):
        return
    creature_damage_runtime.apply_creature_damage(
        idx,
        float(damage),
        int(damage_type),
        impulse,
        owner,
    )


__all__ = [
    "_apply_damage_to_creature",
    "_hit_radius_for",
    "_within_native_find_radius",
    "creature_find_nearest_alive",
    "native_find_size_margin",
]
