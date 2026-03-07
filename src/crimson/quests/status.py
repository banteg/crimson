from __future__ import annotations

from .level import QuestLevel

# `game.cfg` quest counters use staged offsets into `quest_play_counts`.
QUEST_STATUS_GAMES_OFFSET = 11
QUEST_STATUS_COMPLETED_OFFSET = 51
QUEST_STATUS_TRACKED_COUNT = 40


def quest_games_counter_index(level: QuestLevel) -> int:
    return int(level.global_index) + QUEST_STATUS_GAMES_OFFSET


def tracked_quest_games_counter_index(level: QuestLevel) -> int | None:
    if not quest_tracked_in_status(level):
        return None
    return quest_games_counter_index(level)


def quest_completed_counter_index(level: QuestLevel) -> int:
    return int(level.global_index) + QUEST_STATUS_COMPLETED_OFFSET


def quest_tracked_in_status(level: QuestLevel) -> bool:
    return int(level.global_index) < QUEST_STATUS_TRACKED_COUNT


def tracked_quest_completed_counter_index(level: QuestLevel) -> int | None:
    if not quest_tracked_in_status(level):
        return None
    return quest_completed_counter_index(level)
