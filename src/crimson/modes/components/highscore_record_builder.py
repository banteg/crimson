from __future__ import annotations

from ...gameplay import GameplayState, PlayerState, most_used_weapon_id_for_player
from ...persistence.highscores import HighScoreRecord


def clamp_shots(fired: int, hit: int) -> tuple[int, int]:
    fired = max(0, int(fired))
    hit = max(0, min(int(hit), fired))
    return fired, hit


def shots_from_state(state: GameplayState, *, player_index: int) -> tuple[int, int]:
    fired = 0
    hit = 0
    try:
        fired = int(state.shots_fired[int(player_index)])
        hit = int(state.shots_hit[int(player_index)])
    except Exception:
        fired = 0
        hit = 0
    return clamp_shots(fired, hit)


def build_highscore_record_for_game_over(
    *,
    state: GameplayState,
    player: PlayerState,
    survival_elapsed_ms: int,
    creature_kill_count: int,
    game_mode_id: int,
    shots_fired: int | None = None,
    shots_hit: int | None = None,
    clamp_shots_hit: bool = True,
) -> HighScoreRecord:
    record = HighScoreRecord.blank()
    record.score_xp = int(player.experience)
    record.survival_elapsed_ms = int(survival_elapsed_ms)
    record.creature_kill_count = int(creature_kill_count)

    weapon_id = most_used_weapon_id_for_player(
        state, player_index=int(player.index), fallback_weapon_id=int(player.weapon_id)
    )
    record.most_used_weapon_id = int(weapon_id)

    if shots_fired is None or shots_hit is None:
        fired, hit = shots_from_state(state, player_index=int(player.index))
    else:
        fired = int(shots_fired)
        hit = int(shots_hit)
        if clamp_shots_hit:
            fired, hit = clamp_shots(fired, hit)

    record.shots_fired = fired
    record.shots_hit = hit
    record.game_mode_id = int(game_mode_id)
    return record

