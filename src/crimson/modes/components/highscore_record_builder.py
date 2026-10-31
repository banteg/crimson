from __future__ import annotations

from typing import TYPE_CHECKING

from ...persistence.highscores import HighScoreRecord
from ...replay.codec import encode_replay_payload, run_id
from ...replay.types import Replay
from ...sim.run_result import run_shot_counts
from ...sim.state_types import PlayerState
from ...weapon_runtime import most_used_weapon_id_for_player

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


def build_highscore_record(
    *,
    state: GameplayState,
    player: PlayerState,
    run_elapsed_ms: int,
    creature_kill_count: int,
    rand_value: int | None = None,
) -> HighScoreRecord:
    """The run's high-score record; quests pass the tag drawn at quest start, other modes draw it now."""
    record = HighScoreRecord.blank(rand_value=state.rng.rand() if rand_value is None else rand_value)
    record.score_xp = int(state.highscore_score_xp)
    record.run_elapsed_ms = int(run_elapsed_ms)
    record.creature_kill_count = int(creature_kill_count)
    record.most_used_weapon_id = most_used_weapon_id_for_player(
        state,
        fallback_weapon_id=player.weapon.weapon_id,
    )
    record.shots_fired, record.shots_hit = run_shot_counts(state)
    record.game_mode_id = state.game_mode
    record.quest_level = state.quest_level
    record.hardcore = state.hardcore
    record.cl_build = state.cl_build
    return record


def link_highscore_replay(record: HighScoreRecord, number: int, replay: Replay) -> None:
    """Point the record at its saved replay: the file's number, the run's leaderboard id, and its rules."""
    record.replay_number = number
    record.run = run_id(encode_replay_payload(replay))
    record.rules = replay.rules
    record.game_version = replay.game_version
