from __future__ import annotations

import datetime as dt

import msgspec

from crimson.screens.actions import ScoreQuery

from ...game.types import GameState
from ...game_modes import GameMode
from ...leaderboard import Board, OnlineScore
from ...persistence.highscores import (
    HighScoreRecord,
    ScoreTable,
    read_highscore_records,
    select_highscore_table,
)
from ...replay.ranked import board_for
from ...weapons import WeaponId


def online_board(state: GameState, request: ScoreQuery) -> Board | None:
    """The verified board for the scores on screen: Survival and quests, for one player or a co-op pair; other modes
    and teams have none."""
    gameplay = state.config.gameplay
    board = board_for(request.game_mode_id, hardcore=gameplay.hardcore, player_count=gameplay.player_count)
    if board is None:
        return None
    if request.game_mode_id != GameMode.QUESTS:
        return board, ""
    return None if request.quest_level is None else (board, request.quest_level.text)


def _online_record(score: OnlineScore, table: ScoreTable) -> HighScoreRecord:
    return HighScoreRecord(
        name=score.name,
        game_mode_id=table.game_mode_id,
        quest_level=table.quest_level,
        hardcore=table.hardcore,
        player_count=table.player_count,
        score_list=table.score_list,
        score_xp=score.experience,
        # A quest record's time is its final time, which the quest boards rank.
        run_elapsed_ms=score.score if table.game_mode_id == GameMode.QUESTS else score.elapsed_ms,
        most_used_weapon_id=WeaponId(score.most_used_weapon_id),
        shots_fired=score.shots_fired,
        shots_hit=score.shots_hit,
        creature_kill_count=score.kills,
        date=dt.datetime.fromtimestamp(score.accepted_at / 1000, tz=dt.UTC).astimezone().date(),
        run=score.run,
        received=True,
    )


def _run_key(record: HighScoreRecord) -> tuple[str, int, int]:
    return record.name, record.run_elapsed_ms, record.score_xp


def _same_run(local: HighScoreRecord, received: HighScoreRecord) -> bool:
    # A record imported from the original has no run id; it matches by name, time and experience.
    if local.run:
        return local.run == received.run
    return _run_key(local) == _run_key(received)


def _with_online(local: list[HighScoreRecord], online: list[HighScoreRecord]) -> list[HighScoreRecord]:
    """The local records and the received ones; a local run the board holds turns green instead of showing twice, and
    takes the board's run id."""
    unmatched = list(online)
    merged = []
    for record in local:
        board_record = next((same for same in unmatched if _same_run(record, same)), None)
        if board_record is not None:
            unmatched.remove(board_record)
            record = msgspec.structs.replace(record, run=board_record.run, received=True)
        merged.append(record)
    return merged + unmatched


def load_records(state: GameState, request: ScoreQuery) -> list[HighScoreRecord]:
    """`highscore_load_table`: the table's records, with the board's received runs while Show internet scores is on."""
    table = ScoreTable.for_config(state.config, game_mode_id=request.game_mode_id, quest_level=request.quest_level)
    try:
        records = [record for record in read_highscore_records(state.base_dir) if table.holds(record)]
    except OSError:
        records = []
    board = online_board(state, request)
    leaderboard = state.leaderboard
    if state.config.profile.show_internet_scores and leaderboard is not None and board in leaderboard.scores:
        records = _with_online(records, [_online_record(score, table) for score in leaderboard.scores[board]])
    return select_highscore_table(
        records,
        game_mode_id=request.game_mode_id,
        date_mode=state.config.profile.score_date_mode,
        now=dt.datetime.now(tz=dt.UTC).astimezone().date(),
    )


__all__ = ["load_records", "online_board"]
