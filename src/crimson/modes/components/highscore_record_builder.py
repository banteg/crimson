from __future__ import annotations

from typing import TYPE_CHECKING

from ...persistence.highscores import HighScoreRecord
from ...sim.run_result import run_shot_counts
from ...sim.state_types import PlayerState
from ...weapon_runtime import most_used_weapon_id_for_player

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


def build_highscore_record_for_game_over(
    *,
    state: GameplayState,
    player: PlayerState,
    survival_elapsed_ms: int,
    creature_kill_count: int,
) -> HighScoreRecord:
    record = HighScoreRecord.blank(rng=state.rng)
    record.score_xp = int(state.highscore_score_xp)
    record.survival_elapsed_ms = int(survival_elapsed_ms)
    record.creature_kill_count = int(creature_kill_count)
    record.most_used_weapon_id = most_used_weapon_id_for_player(
        state,
        fallback_weapon_id=player.weapon.weapon_id,
    )
    record.shots_fired, record.shots_hit = run_shot_counts(state)
    record.game_mode_id = state.game_mode
    record.hardcore_marker = 0x75 if state.hardcore else 0
    return record
