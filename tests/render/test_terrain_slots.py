from __future__ import annotations

from crimson.quests import all_quests
from crimson.quests.level import QuestLevel
from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q2_TERRAIN_SLOTS,
    Q3_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    TerrainSlotTriplet,
    choose_unlock_terrain_slots,
    terrain_slots_for_quest,
    terrain_slots_to_texture_ids,
)
from grim.assets import TextureId
from tests.support.helpers import ScriptedCrand


def test_terrain_slots_for_quest_matches_native_layout() -> None:
    assert terrain_slots_for_quest(QuestLevel(1, 1)) == DEFAULT_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(4, 5)) == Q4_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(2, 6)) == (2, 2, 3)
    assert terrain_slots_for_quest(QuestLevel(5, 7)) == (3, 1, 3)


def test_choose_unlock_terrain_slots_uses_sequential_unlock_rolls() -> None:
    rng = ScriptedCrand([0, 0, 3])
    chosen = choose_unlock_terrain_slots(
        unlock_index=0x28,
        rng=rng,
    )

    assert chosen == Q2_TERRAIN_SLOTS
    assert [record.caller for record in rng.records_since()] == [
        0x00418229,
        0x00418254,
        0x0041827F,
    ]


def test_choose_unlock_terrain_slots_prefers_first_matching_unlock() -> None:
    rng = ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    chosen = choose_unlock_terrain_slots(
        unlock_index=0x28,
        rng=rng,
    )

    assert chosen == Q4_TERRAIN_SLOTS
    assert [record.caller for record in rng.records_since()] == [0x00418229]


def test_choose_unlock_terrain_slots_keeps_default_below_unlock_thresholds() -> None:
    chosen = choose_unlock_terrain_slots(
        unlock_index=0x13,
        rng=ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert chosen == DEFAULT_TERRAIN_SLOTS


def test_choose_unlock_terrain_slots_can_fall_to_mid_tiers() -> None:
    rng = ScriptedCrand([0, 3])
    chosen = choose_unlock_terrain_slots(
        unlock_index=0x28,
        rng=rng,
    )

    assert chosen == Q3_TERRAIN_SLOTS
    assert [record.caller for record in rng.records_since()] == [
        0x00418229,
        0x00418254,
    ]


def test_all_produced_terrain_slots_map_without_fallback_logic() -> None:
    produced_slots: set[TerrainSlotTriplet] = {quest.terrain_slots for quest in all_quests()}

    for unlock_index in range(51):
        for roll in range(8):
            produced_slots.add(
                choose_unlock_terrain_slots(
                    unlock_index=unlock_index,
                    rng=ScriptedCrand(roll, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                ),
            )

    for slots in sorted(produced_slots):
        texture_ids = terrain_slots_to_texture_ids(slots)
        assert len(texture_ids) == 3
        assert all(isinstance(texture_id, TextureId) for texture_id in texture_ids)
