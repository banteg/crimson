from __future__ import annotations

from crimson.quests import QUESTS
from crimson.quests.level import QuestLevel
from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    TerrainSlotTriplet,
    resolve_terrain_slots,
    terrain_slots_for_quest,
    terrain_slots_to_texture_ids,
)
from grim.assets import TextureId


def test_terrain_slots_for_quest_matches_native_layout() -> None:
    assert terrain_slots_for_quest(QuestLevel(1, 1)) == DEFAULT_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(4, 5)) == Q4_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(2, 6)) == (2, 2, 3)
    assert terrain_slots_for_quest(QuestLevel(5, 7)) == (3, 1, 3)


def test_all_produced_terrain_slots_map_without_fallback_logic() -> None:
    produced_slots: set[TerrainSlotTriplet] = {quest.terrain_slots for quest in QUESTS}
    produced_slots |= {DEFAULT_TERRAIN_SLOTS, Q2_TERRAIN_SLOTS, Q3_TERRAIN_SLOTS, Q4_TERRAIN_SLOTS}

    for slots in sorted(produced_slots):
        texture_ids = terrain_slots_to_texture_ids(slots)
        assert len(texture_ids) == 3
        assert all(isinstance(texture_id, TextureId) for texture_id in texture_ids)


def test_resolve_terrain_slots_uses_lookup_order() -> None:
    values = resolve_terrain_slots(
        (0, 1, 3),
        lambda texture_id: texture_id.name,
    )

    assert values == (
        TextureId.TER_Q1_BASE.name,
        TextureId.TER_Q1_OVERLAY.name,
        TextureId.TER_Q2_OVERLAY.name,
    )
