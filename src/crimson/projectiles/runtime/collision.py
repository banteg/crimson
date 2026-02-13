from __future__ import annotations

import math
from typing import Sequence

from grim.geom import Vec2

from ..types import CreatureDamageApplier, Damageable, _CREATURE_HITBOX_ALIVE, _SizeLike

_NATIVE_FIND_RADIUS_MARGIN_EPS = 0.001


def _hit_radius_for(creature: _SizeLike) -> float:
    """Approximate `creature_find_in_radius`/`creatures_apply_radius_damage` sizing.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    size = float(creature.size)
    return max(0.0, size * 0.14285715 + 3.0)


def _within_native_find_radius(*, origin: Vec2, target: Vec2, radius: float, target_size: float) -> bool:
    """Mirror native `creature_find_in_radius` / `player_find_in_radius` predicate.

    Native uses:
      sqrt(dx*dx + dy*dy) - radius < size * 0.14285715 + 3.0
    """

    dx = float(target.x) - float(origin.x)
    dy = float(target.y) - float(origin.y)
    margin = math.sqrt(dx * dx + dy * dy) - float(radius) - (float(target_size) * 0.14285715 + 3.0)
    # Native uses x87-heavy float math in this path; a tiny epsilon avoids
    # branch flips on sub-millimetric drift from float32 replay state.
    return float(margin) < _NATIVE_FIND_RADIUS_MARGIN_EPS


def _creature_find_nearest_for_secondary(*, creatures: Sequence[Damageable], origin: Vec2) -> int:
    """Port of `creature_find_nearest(origin, -1, 0.0)` for homing secondary targets."""

    best_idx = 0
    best_dist_sq = 1_000_000.0
    max_index = min(len(creatures), 0x180)
    for idx in range(max_index):
        creature = creatures[idx]
        if not creature.active:
            continue
        if float(creature.hitbox_size) != _CREATURE_HITBOX_ALIVE:
            continue
        dist_sq = Vec2.distance_sq(origin, creature.pos)
        if dist_sq < best_dist_sq:
            best_dist_sq = dist_sq
            best_idx = idx
    return best_idx


def _apply_damage_to_creature(
    creatures: Sequence[Damageable],
    creature_index: int,
    damage: float,
    *,
    damage_type: int,
    impulse: Vec2,
    owner_id: int,
    apply_creature_damage: CreatureDamageApplier | None = None,
) -> None:
    if damage <= 0.0:
        return
    idx = int(creature_index)
    if not (0 <= idx < len(creatures)):
        return
    if apply_creature_damage is not None:
        apply_creature_damage(
            idx,
            float(damage),
            int(damage_type),
            impulse,
            int(owner_id),
        )
    else:
        creatures[idx].hp -= float(damage)


__all__ = [
    "_apply_damage_to_creature",
    "_creature_find_nearest_for_secondary",
    "_hit_radius_for",
    "_within_native_find_radius",
]
