from __future__ import annotations

from crimson.persistence.save_status import GameStatusData
from crimson.quests.results import advance_quest_unlocks


def test_normal_completion_advances_only_normal_track() -> None:
    status = GameStatusData(quest_unlock_index=4, quest_unlock_index_full=2)

    advance_quest_unlocks(status, next_unlock=5, hardcore=False)

    assert status.quest_unlock_index == 5
    assert status.quest_unlock_index_full == 2


def test_hardcore_completion_advances_both_tracks() -> None:
    status = GameStatusData(quest_unlock_index=4, quest_unlock_index_full=2)

    advance_quest_unlocks(status, next_unlock=5, hardcore=True)

    assert status.quest_unlock_index == 5
    assert status.quest_unlock_index_full == 5


def test_unlocks_never_regress() -> None:
    status = GameStatusData(quest_unlock_index=10, quest_unlock_index_full=10)

    advance_quest_unlocks(status, next_unlock=5, hardcore=True)

    assert status.quest_unlock_index == 10
    assert status.quest_unlock_index_full == 10
