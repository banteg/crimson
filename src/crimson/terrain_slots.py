from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from grim.assets import TextureId

_QUEST_STAGE_COUNT = 5
_QUESTS_PER_STAGE = 10

TerrainSlotTriplet: TypeAlias = tuple[int, int, int]

Q1_TERRAIN_SLOTS: TerrainSlotTriplet = (0, 1, 0)
Q2_TERRAIN_SLOTS: TerrainSlotTriplet = (2, 3, 2)
Q3_TERRAIN_SLOTS: TerrainSlotTriplet = (4, 5, 4)
Q4_TERRAIN_SLOTS: TerrainSlotTriplet = (6, 7, 6)
DEFAULT_TERRAIN_SLOTS: TerrainSlotTriplet = Q1_TERRAIN_SLOTS

MENU_UNLOCK_TERRAIN_SLOTS: dict[int, TerrainSlotTriplet] = {
    40: Q4_TERRAIN_SLOTS,  # after quest 4.10 "The End of All"
    30: Q3_TERRAIN_SLOTS,  # after quest 3.10 "Zombie Masters"
    20: Q2_TERRAIN_SLOTS,  # after quest 2.10 "Spideroids"
}

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

DEFAULT_TERRAIN_TEXTURE_IDS: tuple[TextureId, TextureId, TextureId] = (
    TextureId.TER_Q1_BASE,
    TextureId.TER_Q1_OVERLAY,
    TextureId.TER_Q1_BASE,
)


def _level_parts(level_or_major: str | int, minor: int | None = None) -> tuple[int, int]:
    if isinstance(level_or_major, str):
        text = str(level_or_major).strip()
        major_text, sep, minor_text = text.partition(".")
        if sep != "." or not major_text or not minor_text:
            raise ValueError(f"invalid quest level: {level_or_major!r}")
        try:
            major = int(major_text)
            minor = int(minor_text)
        except ValueError as exc:
            raise ValueError(f"invalid quest level: {level_or_major!r}") from exc
        if not (1 <= major <= _QUEST_STAGE_COUNT):
            raise ValueError(f"quest stage out of range: {major} (expected 1..{_QUEST_STAGE_COUNT})")
        if not (1 <= minor <= _QUESTS_PER_STAGE):
            raise ValueError(f"quest row out of range: {minor} (expected 1..{_QUESTS_PER_STAGE})")
        return major, minor
    if minor is None:
        raise TypeError("minor is required when major is passed as an int")
    major = int(level_or_major)
    quest = int(minor)
    if not (1 <= major <= _QUEST_STAGE_COUNT):
        raise ValueError(f"quest stage out of range: {major} (expected 1..{_QUEST_STAGE_COUNT})")
    if not (1 <= quest <= _QUESTS_PER_STAGE):
        raise ValueError(f"quest row out of range: {quest} (expected 1..{_QUESTS_PER_STAGE})")
    return major, quest


def terrain_slots_for_level(level_or_major: str | int, minor: int | None = None) -> TerrainSlotTriplet:
    tier, quest = _level_parts(level_or_major, minor)
    if tier <= 4:
        base = (tier - 1) * 2
        alt = base + 1
        if quest < 6:
            return base, alt, base
        return base, base, alt
    return quest & 0x3, 1, 3


def choose_menu_terrain_slots(
    *,
    quest_unlock_index: int,
    rand: Callable[[], int],
) -> TerrainSlotTriplet:
    unlock_index = int(quest_unlock_index)
    for threshold, slots in MENU_UNLOCK_TERRAIN_SLOTS.items():
        if unlock_index >= int(threshold) and (int(rand()) & 7) == 3:
            return slots
    return DEFAULT_TERRAIN_SLOTS


def terrain_slots_to_texture_ids(
    slots: TerrainSlotTriplet | None,
) -> tuple[TextureId, TextureId, TextureId]:
    if slots is None:
        return DEFAULT_TERRAIN_TEXTURE_IDS
    try:
        base = _TEXTURE_ID_BY_TERRAIN_SLOT[int(slots[0])]
        overlay = _TEXTURE_ID_BY_TERRAIN_SLOT[int(slots[1])]
        detail = _TEXTURE_ID_BY_TERRAIN_SLOT[int(slots[2])]
    except (KeyError, TypeError, ValueError, IndexError):
        return DEFAULT_TERRAIN_TEXTURE_IDS
    return base, overlay, detail


__all__ = [
    "DEFAULT_TERRAIN_SLOTS",
    "DEFAULT_TERRAIN_TEXTURE_IDS",
    "MENU_UNLOCK_TERRAIN_SLOTS",
    "Q1_TERRAIN_SLOTS",
    "Q2_TERRAIN_SLOTS",
    "Q3_TERRAIN_SLOTS",
    "Q4_TERRAIN_SLOTS",
    "TerrainSlotTriplet",
    "choose_menu_terrain_slots",
    "terrain_slots_for_level",
    "terrain_slots_to_texture_ids",
]
