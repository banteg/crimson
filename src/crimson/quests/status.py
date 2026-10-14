from __future__ import annotations

from .level import QuestLevel

# `game.cfg.quest_play_counts` only has dedicated quest slots for quests 1.1..4.10:
# - attempts live at indices 11..50
# - completions live at indices 51..90
# Stage 5 has no dedicated slots in the original blob layout, so callers that
# need the "tracked in save data" subset must use the `tracked_...` helpers
# instead of the raw offset helpers below.
QUEST_STATUS_GAMES_OFFSET = 11
QUEST_STATUS_COMPLETED_OFFSET = 51
QUEST_STATUS_TRACKED_COUNT = 40


def quest_games_counter_index(level: QuestLevel) -> int:
    return int(level.global_index) + QUEST_STATUS_GAMES_OFFSET


def tracked_quest_games_counter_index(level: QuestLevel) -> int | None:
    """Return the persisted attempts slot for quest levels that fit in game.cfg."""

    if not quest_tracked_in_status(level):
        return None
    return quest_games_counter_index(level)


def quest_completed_counter_index(level: QuestLevel) -> int:
    return int(level.global_index) + QUEST_STATUS_COMPLETED_OFFSET


def quest_tracked_in_status(level: QuestLevel) -> bool:
    return int(level.global_index) < QUEST_STATUS_TRACKED_COUNT


def tracked_quest_completed_counter_index(level: QuestLevel) -> int | None:
    """Return the persisted completion slot for quest levels that fit in game.cfg."""

    if not quest_tracked_in_status(level):
        return None
    return quest_completed_counter_index(level)
