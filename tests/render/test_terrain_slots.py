from __future__ import annotations

from crimson.quests.level import QuestLevel
from crimson.terrain_slots import (
    DEFAULT_TERRAIN_SLOTS,
    Q4_TERRAIN_SLOTS,
    terrain_slots_for_quest,
)


def test_terrain_slots_for_quest_matches_native_layout() -> None:
    assert terrain_slots_for_quest(QuestLevel(1, 1)) == DEFAULT_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(4, 5)) == Q4_TERRAIN_SLOTS
    assert terrain_slots_for_quest(QuestLevel(2, 6)) == (2, 2, 3)
    assert terrain_slots_for_quest(QuestLevel(5, 7)) == (3, 1, 3)
