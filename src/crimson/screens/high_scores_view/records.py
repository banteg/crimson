from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from ...game.types import GameState, HighScoresRequest
from ...game_modes import GameMode
from ...quests.level import QuestLevel

if TYPE_CHECKING:
    from ...persistence.highscores import HighScoreRecord


def resolve_request(state: GameState) -> HighScoresRequest:
    request = state.pending_high_scores
    state.pending_high_scores = None
    if request is None:
        request = HighScoresRequest(game_mode_id=GameMode(state.config.gameplay.mode))

    if request.game_mode_id == GameMode.QUESTS and request.quest_level is None:
        level = state.pending_quest_level
        if level is None:
            level = state.config.gameplay.quest_level
        # Native screen always has a valid quest stage selected (defaults to 1.1).
        request.quest_level = level if level is not None else QuestLevel(1, 1)

    return request


def _passes_date_filter(entry: "HighScoreRecord", *, date_mode: int, now: dt.date) -> bool:
    # Native `config_highscore_date_mode` values (see highscore_screen_update):
    #   0 = Best of all time (no filter)
    #   1 = Best of month
    #   2 = Best of week
    #   3 = Best of day
    mode = int(date_mode)
    if mode <= 0:
        return True

    day = int(entry.day)
    month = int(entry.month)
    year_off = int(entry.year_offset)
    if day <= 0 or month <= 0:
        return False
    year = 2000 + year_off
    if mode == 1:
        return int(month) == int(now.month) and int(year) == int(now.year)
    if mode == 3:
        return int(day) == int(now.day) and int(month) == int(now.month) and int(year) == int(now.year)
    if mode == 2:
        # Native `dateWeek`: week-of-year checksum stored at record byte 0x41.
        from ...persistence.highscores import highscore_date_week

        stored = int(entry.date_week)
        checksum = int(highscore_date_week(now.year, now.month, now.day))
        return int(stored) == int(checksum) and int(year) == int(now.year)
    return True


def load_records(state: GameState, request: HighScoresRequest) -> list[HighScoreRecord]:
    from ...persistence.highscores import read_highscore_table, scores_path_for_mode

    path = scores_path_for_mode(
        state.base_dir,
        request.game_mode_id,
        hardcore=state.config.gameplay.hardcore,
        quest_stage_major=(0 if request.quest_level is None else int(request.quest_level.major)),
        quest_stage_minor=(0 if request.quest_level is None else int(request.quest_level.minor)),
        player_count=state.config.gameplay.player_count,
    )
    try:
        records = read_highscore_table(path, game_mode_id=request.game_mode_id)
    except (OSError, ValueError):
        return []
    date_mode = int(state.config.profile.score_date_mode)
    if date_mode > 0:
        now = dt.date.today()
        records = [entry for entry in records if _passes_date_filter(entry, date_mode=date_mode, now=now)]
    return records


__all__ = ["load_records", "resolve_request"]
