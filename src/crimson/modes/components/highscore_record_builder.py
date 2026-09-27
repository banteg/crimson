from __future__ import annotations

from typing import TYPE_CHECKING

from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...sim.state_types import PlayerState
from ...typo.state import typo_shot_counts
from ...weapon_runtime import most_used_weapon_id_for_player

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


def clamp_shots(fired: int, hit: int) -> tuple[int, int]:
    fired = max(0, int(fired))
    hit = max(0, min(int(hit), fired))
    return fired, hit


def shots_from_state(state: GameplayState, *, player_index: int) -> tuple[int, int]:
    index = int(player_index)
    if index < 0 or index >= len(state.shots_fired) or index >= len(state.shots_hit):
        return 0, 0
    fired = int(state.shots_fired[index])
    hit = int(state.shots_hit[index])
    return clamp_shots(fired, hit)


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
    if state.game_mode == GameMode.TYPO:
        # Typ-o counts typed words, not gun shots, and stores them unclamped.
        record.shots_fired, record.shots_hit = typo_shot_counts(state.typo)
    else:
        record.shots_fired, record.shots_hit = shots_from_state(state, player_index=int(player.index))
    record.game_mode_id = state.game_mode
    record.hardcore_marker = 0x75 if state.hardcore else 0
    return record
