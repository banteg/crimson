from __future__ import annotations

from .shared import parse_quest_level
from ..types import GameState, HighScoresRequest


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
        request.quest_stage_major = int(major)
        request.quest_stage_minor = int(minor)

    return request


def load_records(state: GameState, request: HighScoresRequest) -> list:
    from ...persistence.highscores import read_highscore_table, scores_path_for_mode

    path = scores_path_for_mode(
        state.base_dir,
        int(request.game_mode_id),
        hardcore=state.config.hardcore,
        quest_stage_major=int(request.quest_stage_major),
        quest_stage_minor=int(request.quest_stage_minor),
    )
    try:
        return read_highscore_table(path, game_mode_id=int(request.game_mode_id))
    except Exception:
        return []


__all__ = ["load_records", "resolve_request"]
