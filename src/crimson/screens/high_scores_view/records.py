from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.screens.actions import ScoreQuery

from ...game.types import GameState

if TYPE_CHECKING:
    from ...persistence.highscores import HighScoreRecord


def load_records(state: GameState, request: ScoreQuery) -> list[HighScoreRecord]:
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
        return read_highscore_table(
            path, game_mode_id=request.game_mode_id, date_mode=state.config.profile.score_date_mode,
        )
    except (OSError, ValueError):
        return []


__all__ = ["load_records"]
