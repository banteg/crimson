from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.game_version import REPLAY_RULES
from crimson.persistence.highscores import HighScoreRecord
from crimson.replay import ReplayRecorder, dump_replay_file
from crimson.replay.input_codec import pack_tick
from crimson.replay.library import replay_file_name
from crimson.screens.high_scores_view.records import _with_online
from crimson.screens.high_scores_view.watch import WatchTarget, local_watch_target
from crimson.sim.run_spec import RunSpec
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import finish_replay


def _record(number: int) -> HighScoreRecord:
    record = HighScoreRecord.blank(rand_value=0)
    record.replay_number = number
    return record


def _save(replay_dir: Path, number: int, **changes) -> None:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=3))
    recorder.record(pack_tick([player_input()], []))
    replay = msgspec.structs.replace(finish_replay(recorder), **changes)
    replay_dir.mkdir(exist_ok=True)
    dump_replay_file(replay_dir / replay_file_name(number, GameMode.SURVIVAL), replay)


def test_a_rows_replay_plays_or_says_why_not(tmp_path: Path) -> None:
    _save(tmp_path, 1)
    _save(tmp_path, 2, game_version="0.12.2+gabc123def456")
    _save(tmp_path, 3, rules=REPLAY_RULES + 1, game_version="9.0.0")
    (tmp_path / replay_file_name(4, GameMode.SURVIVAL)).write_bytes(b"not a replay")

    playable = local_watch_target(tmp_path, _record(1))
    assert playable is not None and playable.replay is not None and playable.note == ""
    other_build = local_watch_target(tmp_path, _record(2))
    assert other_build is not None and other_build.replay is not None and other_build.note == "Recorded with 0.12.2"

    assert local_watch_target(tmp_path, _record(3)) == WatchTarget(None, "Recorded under other rules (9.0.0)")
    unreadable = local_watch_target(tmp_path, _record(4))
    assert unreadable == WatchTarget(None, "This version cannot read its replay")
    missing = local_watch_target(tmp_path, _record(5))
    assert missing is not None and missing.replay is None and missing.note == "Its replay was not saved"
    assert local_watch_target(tmp_path, _record(0)) is None


def test_each_board_row_keeps_its_own_run_and_a_local_run_on_the_board_takes_its_id() -> None:
    def received(run: str) -> HighScoreRecord:
        record = HighScoreRecord.blank(rand_value=0)
        record.set_name("twin")
        record.run = run
        return record

    local = HighScoreRecord.blank(rand_value=0)
    local.set_name("twin")
    local.replay_number = 4

    merged = _with_online([local], [received("a" * 64), received("b" * 64)])

    # The local run takes the first board row's id and keeps its own replay; the other board row stays.
    assert [(record.replay_number, record.run) for record in merged] == [(4, "a" * 64), (0, "b" * 64)]
    assert local.run == ""
