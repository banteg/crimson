from __future__ import annotations

from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    choose_menu_terrain_slots,
    terrain_slots_for_level,
)


def test_terrain_slots_for_level_matches_native_layout() -> None:
    assert terrain_slots_for_level("1.1") == DEFAULT_TERRAIN_SLOTS
    assert terrain_slots_for_level("4.5") == Q4_TERRAIN_SLOTS
    assert terrain_slots_for_level("2.6") == (2, 2, 3)
    assert terrain_slots_for_level("5.7") == (3, 1, 3)


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
