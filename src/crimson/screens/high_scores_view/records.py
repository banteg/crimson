from __future__ import annotations

import datetime as dt

from crimson.screens.actions import ScoreQuery

from ...game.types import GameState
from ...game_modes import GameMode
from ...leaderboard import Board, OnlineScore
from ...persistence.highscores import (
    HighScoreRecord,
    read_highscore_records,
    scores_path_for_mode,
    select_highscore_table,
)
from ...weapons import WeaponId

# `highscore_sync_worker` marks received records: flag bit 0 draws them green, and quest records carry the
# hardcore marker.
RECEIVED_FLAG = 1
HARDCORE_MARKER = 0x75


def online_board(state: GameState, request: ScoreQuery) -> Board | None:
    """The verified board for the scores on screen: one-player Survival and quests; other modes have none."""
    if state.config.gameplay.player_count != 1:
        return None
    match request.game_mode_id:
        case GameMode.SURVIVAL:
            return "survival", ""
        case GameMode.QUESTS if request.quest_level is not None:
            return "quests-hardcore" if state.config.gameplay.hardcore else "quests", request.quest_level.text
    return None


def _online_record(score: OnlineScore, request: ScoreQuery, *, hardcore: bool) -> HighScoreRecord:
    record = HighScoreRecord.blank(rand_value=0)
    record.set_name(score.name)
    record.game_mode_id = request.game_mode_id
    record.quest_level = request.quest_level
    record.score_xp = score.experience
    # A quest record's time is its final time, which the quest boards rank.
    record.run_elapsed_ms = score.score if request.game_mode_id == GameMode.QUESTS else score.elapsed_ms
    record.most_used_weapon_id = WeaponId(score.most_used_weapon_id)
    record.shots_fired = score.shots_fired
    record.shots_hit = score.shots_hit
    record.creature_kill_count = score.kills
    record.ensure_date_fields(dt.datetime.fromtimestamp(score.accepted_at / 1000, tz=dt.UTC).astimezone().date())
    record.flags = RECEIVED_FLAG
    record.hardcore_marker = HARDCORE_MARKER if hardcore and request.game_mode_id == GameMode.QUESTS else 0
    return record


def run_key(record: HighScoreRecord) -> tuple[str, int, int]:
    return record.name(), record.run_elapsed_ms, record.score_xp


def online_runs(state: GameState, request: ScoreQuery) -> dict[tuple[str, int, int], str]:
    """The run id of each received row on screen, by the row's run key, so Watch can download its replay."""
    board = online_board(state, request)
    leaderboard = state.leaderboard
    if leaderboard is None or board not in leaderboard.scores:
        return {}
    hardcore = state.config.gameplay.hardcore
    return {run_key(_online_record(score, request, hardcore=hardcore)): score.run for score in leaderboard.scores[board] if score.run}


def _with_online(local: list[HighScoreRecord], online: list[HighScoreRecord]) -> list[HighScoreRecord]:
    """The local records and the received ones; a local run the board holds turns green instead of showing twice."""
    received = {run_key(record): record for record in online}
    merged = []
    for record in local:
        if received.pop(run_key(record), None) is not None:
            record = record.copy()
            record.flags |= RECEIVED_FLAG
        merged.append(record)
    return merged + list(received.values())


def load_records(state: GameState, request: ScoreQuery) -> list[HighScoreRecord]:
    """`highscore_load_table`: the table's records, with the board's received runs while Show internet scores is on."""
    path = scores_path_for_mode(
        state.base_dir,
        request.game_mode_id,
        hardcore=state.config.gameplay.hardcore,
        quest_stage_major=(0 if request.quest_level is None else int(request.quest_level.major)),
        quest_stage_minor=(0 if request.quest_level is None else int(request.quest_level.minor)),
        player_count=state.config.gameplay.player_count,
        named_list=state.config.profile.named_score_list,
    )
    try:
        records = read_highscore_records(path)
    except (OSError, ValueError):
        records = []
    board = online_board(state, request)
    leaderboard = state.leaderboard
    if state.config.profile.show_internet_scores and leaderboard is not None and board in leaderboard.scores:
        hardcore = state.config.gameplay.hardcore
        records = _with_online(records, [_online_record(score, request, hardcore=hardcore) for score in leaderboard.scores[board]])
    return select_highscore_table(
        records,
        game_mode_id=request.game_mode_id,
        date_mode=state.config.profile.score_date_mode,
        now=dt.datetime.now(tz=dt.UTC).astimezone().date(),
    )


__all__ = ["load_records", "online_board", "online_runs", "run_key"]
