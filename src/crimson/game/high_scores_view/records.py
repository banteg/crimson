from __future__ import annotations

import datetime as dt

from ..types import GameState, HighScoresRequest
from .shared import parse_quest_level


def resolve_request(state: GameState) -> HighScoresRequest:
    request = state.pending_high_scores
    state.pending_high_scores = None
    if request is None:
        request = HighScoresRequest(game_mode_id=state.config.game_mode)

    if int(request.game_mode_id) == 3 and (
        int(request.quest_stage_major) <= 0 or int(request.quest_stage_minor) <= 0
    ):
        major, minor = parse_quest_level(state.pending_quest_level)
        if major <= 0 or minor <= 0:
            major, minor = parse_quest_level(state.config.quest_level)
        if major <= 0 or minor <= 0:
            major = state.config.quest_stage_major
            minor = state.config.quest_stage_minor
        # Native screen always has a valid quest stage selected (defaults to 1.1).
        if major <= 0 or minor <= 0:
            major, minor = 1, 1
        major = max(1, min(5, int(major)))
        minor = max(1, min(10, int(minor)))
        request.quest_stage_major = int(major)
        request.quest_stage_minor = int(minor)

    return request


def _passes_date_filter(entry: object, *, date_mode: int, now: dt.date) -> bool:
    # Native `config_highscore_date_mode` values (see highscore_screen_update):
    #   0 = Best of all time (no filter)
    #   1 = Best of month
    #   2 = Best of week
    #   3 = Best of day
    mode = int(date_mode)
    if mode <= 0:
        return True

    try:
        day = int(getattr(entry, "day", 0) or 0)
        month = int(getattr(entry, "month", 0) or 0)
        year_off = int(getattr(entry, "year_offset", 0) or 0)
    except (TypeError, ValueError):
        return False
    if day <= 0 or month <= 0:
        return False
    year = 2000 + year_off
    if mode == 1:
        return int(month) == int(now.month) and int(year) == int(now.year)
    if mode == 3:
        return int(day) == int(now.day) and int(month) == int(now.month) and int(year) == int(now.year)
    if mode == 2:
        # Week-of-year checksum stored at record byte 0x41.
        from ...persistence.highscores import highscore_date_checksum

        try:
            stored = int(getattr(entry, "data")[0x41])
        except (AttributeError, IndexError, TypeError, ValueError):
            return False
        checksum = int(highscore_date_checksum(now.year, now.month, now.day))
        return int(stored) == int(checksum) and int(year) == int(now.year)
    return True


def load_records(state: GameState, request: HighScoresRequest) -> list:
    from ...persistence.highscores import read_highscore_table, scores_path_for_mode

    path = scores_path_for_mode(
        state.base_dir,
        int(request.game_mode_id),
        hardcore=state.config.hardcore,
        quest_stage_major=int(request.quest_stage_major),
        quest_stage_minor=int(request.quest_stage_minor),
        player_count=state.config.player_count,
    )
    try:
        records = read_highscore_table(path, game_mode_id=int(request.game_mode_id))
    except (OSError, ValueError):
        return []
    date_mode = int(state.config.highscore_date_mode)
    if date_mode > 0:
        now = dt.date.today()
        records = [entry for entry in records if _passes_date_filter(entry, date_mode=date_mode, now=now)]
    return records


__all__ = ["load_records", "resolve_request"]
