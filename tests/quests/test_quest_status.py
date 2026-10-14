from __future__ import annotations

from crimson.quests.level import QuestLevel
from crimson.quests.status import (
    quest_completed_counter_index,
    quest_games_counter_index,
    tracked_quest_completed_counter_index,
    tracked_quest_games_counter_index,
)


def test_tracked_quest_counter_indices_cover_only_quests_1_1_through_4_10() -> None:
    assert tracked_quest_games_counter_index(QuestLevel(4, 10)) == 50
    assert tracked_quest_completed_counter_index(QuestLevel(4, 10)) == 90

    assert tracked_quest_games_counter_index(QuestLevel(5, 1)) is None
    assert tracked_quest_completed_counter_index(QuestLevel(5, 1)) is None


def test_raw_quest_counter_indices_still_model_native_stage5_overflow_offsets() -> None:
    assert quest_games_counter_index(QuestLevel(5, 1)) == 51
    assert quest_completed_counter_index(QuestLevel(5, 1)) == 91
