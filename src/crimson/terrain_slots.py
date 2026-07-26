from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from grim.assets import TextureId
from grim.rand import CrandLike

from .rng_caller_static import RngCallerStatic

if TYPE_CHECKING:
    from .quests.level import QuestLevel

type TerrainSlotTriplet = tuple[int, int, int]

Q1_TERRAIN_SLOTS: TerrainSlotTriplet = (0, 1, 0)
Q2_TERRAIN_SLOTS: TerrainSlotTriplet = (2, 3, 2)
Q3_TERRAIN_SLOTS: TerrainSlotTriplet = (4, 5, 4)
Q4_TERRAIN_SLOTS: TerrainSlotTriplet = (6, 7, 6)
DEFAULT_TERRAIN_SLOTS: TerrainSlotTriplet = Q1_TERRAIN_SLOTS

UNLOCK_TERRAIN_SLOTS: dict[int, TerrainSlotTriplet] = {
    40: Q4_TERRAIN_SLOTS,  # after quest 4.10 "The End of All"
    30: Q3_TERRAIN_SLOTS,  # after quest 3.10 "Zombie Masters"
    20: Q2_TERRAIN_SLOTS,  # after quest 2.10 "Spideroids"
}

_UNLOCK_TERRAIN_RULES: tuple[tuple[int, TerrainSlotTriplet, RngCallerStatic], ...] = (
    (40, Q4_TERRAIN_SLOTS, RngCallerStatic.UNLOCK_TERRAIN_Q4),
    (30, Q3_TERRAIN_SLOTS, RngCallerStatic.UNLOCK_TERRAIN_Q3),
    (20, Q2_TERRAIN_SLOTS, RngCallerStatic.UNLOCK_TERRAIN_Q2),
)

_TEXTURE_ID_BY_TERRAIN_SLOT: dict[int, TextureId] = {
    0: TextureId.TER_Q1_BASE,
    1: TextureId.TER_Q1_OVERLAY,
    2: TextureId.TER_Q2_BASE,
    3: TextureId.TER_Q2_OVERLAY,
    4: TextureId.TER_Q3_BASE,
    5: TextureId.TER_Q3_OVERLAY,
    6: TextureId.TER_Q4_BASE,
    7: TextureId.TER_Q4_OVERLAY,
}


def terrain_slots_for_quest(level: QuestLevel) -> TerrainSlotTriplet:
    if level.major <= 4:
        base = (level.major - 1) * 2
        alt = base + 1
        if level.minor < 6:
            return base, alt, base
        return base, base, alt
    return level.minor & 3, 1, 3


def choose_unlock_terrain_slots(
    *,
    unlock_index: int,
    rng: CrandLike,
) -> TerrainSlotTriplet:
    # Keep the thresholds descending to preserve the native chained 1/8 roll order.
    for threshold, slots, caller in _UNLOCK_TERRAIN_RULES:
        if unlock_index >= threshold and (rng.rand_tagged(caller) & 7) == 3:
            return slots
    return DEFAULT_TERRAIN_SLOTS


def terrain_slots_to_texture_ids(
    slots: TerrainSlotTriplet,
) -> tuple[TextureId, TextureId, TextureId]:
    return (
        _TEXTURE_ID_BY_TERRAIN_SLOT[slots[0]],
        _TEXTURE_ID_BY_TERRAIN_SLOT[slots[1]],
        _TEXTURE_ID_BY_TERRAIN_SLOT[slots[2]],
    )


def resolve_terrain_slots[T](
    slots: TerrainSlotTriplet,
    lookup: Callable[[TextureId], T],
) -> tuple[T, T, T]:
    base_id, overlay_id, detail_id = terrain_slots_to_texture_ids(slots)
    return lookup(base_id), lookup(overlay_id), lookup(detail_id)


__all__ = [
    "DEFAULT_TERRAIN_SLOTS",
    "Q1_TERRAIN_SLOTS",
    "Q2_TERRAIN_SLOTS",
    "Q3_TERRAIN_SLOTS",
    "Q4_TERRAIN_SLOTS",
    "UNLOCK_TERRAIN_SLOTS",
    "TerrainSlotTriplet",
    "choose_unlock_terrain_slots",
    "resolve_terrain_slots",
    "terrain_slots_for_quest",
    "terrain_slots_to_texture_ids",
]
