from __future__ import annotations

from typing import TYPE_CHECKING

from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...sim.state_types import PlayerState
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
    game_mode_id: GameMode,
    shots_fired: int | None = None,
    shots_hit: int | None = None,
    clamp_shots_hit: bool = True,
    hardcore: bool = False,
) -> HighScoreRecord:
    record = HighScoreRecord.blank(rng=state.rng)
    record.score_xp = int(state.highscore_score_xp)
    record.survival_elapsed_ms = int(survival_elapsed_ms)
    record.creature_kill_count = int(creature_kill_count)

    weapon_id = most_used_weapon_id_for_player(
        state,
        player_index=int(player.index),
        fallback_weapon_id=player.weapon.weapon_id,
    )
    record.most_used_weapon_id = weapon_id

    if shots_fired is None or shots_hit is None:
        fired, hit = shots_from_state(state, player_index=int(player.index))
    else:
        fired = int(shots_fired)
        hit = int(shots_hit)
        if clamp_shots_hit:
            fired, hit = clamp_shots(fired, hit)

    record.shots_fired = fired
    record.shots_hit = hit
    record.game_mode_id = game_mode_id
    record.hardcore_marker = 0x75 if bool(hardcore) else 0
    return record
