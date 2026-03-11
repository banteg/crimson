from __future__ import annotations

from typing import TypeAlias

from grim.assets import TextureId
from grim.rand import CrandLike

from .quests.level import QuestLevel

TerrainSlotTriplet: TypeAlias = tuple[int, int, int]

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

_UNLOCK_TERRAIN_Q4_CALLER = 0x00418229
_UNLOCK_TERRAIN_Q3_CALLER = 0x00418254
_UNLOCK_TERRAIN_Q2_CALLER = 0x0041827F

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
    for threshold, slots in UNLOCK_TERRAIN_SLOTS.items():
        caller = None
        if threshold == 40:
            caller = _UNLOCK_TERRAIN_Q4_CALLER
        elif threshold == 30:
            caller = _UNLOCK_TERRAIN_Q3_CALLER
        elif threshold == 20:
            caller = _UNLOCK_TERRAIN_Q2_CALLER
        if unlock_index >= threshold and (rng.rand(caller=caller) & 7) == 3:
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


__all__ = [
    "DEFAULT_TERRAIN_SLOTS",
    "UNLOCK_TERRAIN_SLOTS",
    "Q1_TERRAIN_SLOTS",
    "Q2_TERRAIN_SLOTS",
    "Q3_TERRAIN_SLOTS",
    "Q4_TERRAIN_SLOTS",
    "TerrainSlotTriplet",
    "choose_unlock_terrain_slots",
    "terrain_slots_for_quest",
    "terrain_slots_to_texture_ids",
]
