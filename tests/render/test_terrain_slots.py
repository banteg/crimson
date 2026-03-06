from __future__ import annotations

from crimson.quests import all_quests
from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    TerrainSlotTriplet,
    choose_menu_terrain_slots,
    terrain_slots_for_level,
    terrain_slots_to_texture_ids,
)
from grim.assets import TextureId


def test_terrain_slots_for_level_matches_native_layout() -> None:
    assert terrain_slots_for_level(1, 1) == DEFAULT_TERRAIN_SLOTS
    assert terrain_slots_for_level(4, 5) == Q4_TERRAIN_SLOTS
    assert terrain_slots_for_level(2, 6) == (2, 2, 3)
    assert terrain_slots_for_level(5, 7) == (3, 1, 3)


def test_choose_menu_terrain_slots_uses_sequential_unlock_rolls() -> None:
    rolls = iter((0, 0, 3))

    chosen = choose_menu_terrain_slots(
        quest_unlock_index=0x28,
        rand=lambda: next(rolls),
    )

    assert chosen == Q2_TERRAIN_SLOTS


def test_choose_menu_terrain_slots_prefers_first_matching_unlock() -> None:
    chosen = choose_menu_terrain_slots(
        quest_unlock_index=0x28,
        rand=lambda: 3,
    )

    assert chosen == Q4_TERRAIN_SLOTS


def test_choose_menu_terrain_slots_keeps_default_below_unlock_thresholds() -> None:
    chosen = choose_menu_terrain_slots(
        quest_unlock_index=0x13,
        rand=lambda: 3,
    )

    assert chosen == DEFAULT_TERRAIN_SLOTS


def test_choose_menu_terrain_slots_can_fall_to_mid_tiers() -> None:
    rolls = iter((0, 3))

    chosen = choose_menu_terrain_slots(
        quest_unlock_index=0x28,
        rand=lambda: next(rolls),
    )

    assert chosen == Q3_TERRAIN_SLOTS


def test_all_produced_terrain_slots_map_without_fallback_logic() -> None:
    produced_slots: set[TerrainSlotTriplet] = {quest.terrain_slots for quest in all_quests()}

    for unlock_index in range(51):
        for roll in range(8):
            produced_slots.add(
                choose_menu_terrain_slots(
                    quest_unlock_index=unlock_index,
                    rand=lambda r=roll: r,
                ),
            )

    for slots in sorted(produced_slots):
        texture_ids = terrain_slots_to_texture_ids(slots)
        assert len(texture_ids) == 3
        assert all(isinstance(texture_id, TextureId) for texture_id in texture_ids)
