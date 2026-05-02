from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2

from ...collision_math import native_find_size_margin
from ...creatures.damage_runtime import CreatureDamageRuntime
from ...creatures.lifecycle import creature_lifecycle_is_alive
from ...owner_ref import OwnerRef

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureState

# Keep strict native boundary semantics for collision acceptance.
_NATIVE_FIND_RADIUS_MARGIN_EPS = 0.0


def _hit_radius_for(creature: CreatureState) -> float:
    """Approximate `creature_find_in_radius`/`creatures_apply_radius_damage` sizing.

    The native code compares `distance - radius < creature.size * 0.14285715 + 3.0`.
    """

    return max(0.0, native_find_size_margin(float(creature.size)))


def _within_native_find_radius(*, origin: Vec2, target: Vec2, radius: float, target_size: float) -> bool:
    """Mirror native `creature_find_in_radius` / `player_find_in_radius` predicate.

    Native uses:
      sqrt(dx*dx + dy*dy) - radius < size * 0.14285715 + 3.0
    """

    dx = float(target.x) - float(origin.x)
    dy = float(target.y) - float(origin.y)
    radius_f = float(radius)
    size_margin = native_find_size_margin(float(target_size))
    max_axis_delta = float(radius_f) + float(size_margin) + _NATIVE_FIND_RADIUS_MARGIN_EPS
    # Fast reject for the common case where either axis already exceeds the
    # maximal accepted Euclidean radius.
    if abs(float(dx)) > float(max_axis_delta) or abs(float(dy)) > float(max_axis_delta):
        return False
    margin = math.sqrt(dx * dx + dy * dy) - float(radius_f) - float(size_margin)
    # Native compares against zero; keep strict threshold to avoid rewrite-only
    # near-edge hits that can cascade into RNG/XP timing drift.
    return float(margin) < _NATIVE_FIND_RADIUS_MARGIN_EPS


def _creature_find_nearest_for_secondary(
    *,
    creatures: Sequence[CreatureState],
    origin: Vec2,
    preserve_bugs: bool = False,
) -> int:
    """Port of `creature_find_nearest(origin, -1, 0.0)` for homing secondary targets."""

    best_idx = 0 if preserve_bugs else -1
    best_dist_sq = 1_000_000.0
    max_index = min(len(creatures), 0x180)
    for idx in range(max_index):
        creature = creatures[idx]
        if not creature.active:
            continue
        if not creature_lifecycle_is_alive(creature.lifecycle_stage):
            continue
        dist_sq = Vec2.distance_sq(origin, creature.pos)
        if dist_sq < best_dist_sq:
            best_dist_sq = dist_sq
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
    "_creature_find_nearest_for_secondary",
    "_hit_radius_for",
    "_within_native_find_radius",
    "native_find_size_margin",
]
