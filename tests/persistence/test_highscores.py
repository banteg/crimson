from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.persistence.highscores import (
    HighScoreRecord,
    ScoreTable,
    append_highscore_records,
    rank_index,
    read_highscore_records,
    read_highscore_table,
    scores_path,
    sort_highscores,
    upsert_highscore_record,
)
from crimson.quests.level import QuestLevel
from grim.config import HighScoreDateMode, default_crimson_cfg

SURVIVAL = ScoreTable(GameMode.SURVIVAL)


def test_table_uses_configured_quest_and_clears_nonquest_stages() -> None:
    config = default_crimson_cfg()
    config.gameplay.mode = GameMode.QUESTS
    config.gameplay.quest_level = QuestLevel(2, 7)
    assert ScoreTable.for_config(config).quest_level == QuestLevel(2, 7)
    assert ScoreTable.for_config(config, quest_level=QuestLevel(1, 1)).quest_level == QuestLevel(1, 1)
    stale = HighScoreRecord(game_mode_id=GameMode.QUESTS, quest_level=QuestLevel(2, 7))
    assert SURVIVAL.stamp(stale).quest_level is None


@pytest.mark.parametrize("name, expected", [("Player  ", "Player"), ("   ", " "), ("", "")])
def test_saved_names_trim_with_native_first_character_rule(tmp_path: Path, name: str, expected: str) -> None:
    record = HighScoreRecord(name=name, game_mode_id=GameMode.SURVIVAL)
    upsert_highscore_record(tmp_path, SURVIVAL, record)
    assert read_highscore_records(tmp_path)[0].name == expected
    assert record.name == name


@pytest.mark.parametrize("mode", [GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS])
def test_signed_ranking_matches_sorted_order_including_empty_quest_times(mode: GameMode) -> None:
    records = [
        HighScoreRecord(game_mode_id=mode, run_elapsed_ms=value, score_xp=value & 0xFFFFFFFF)
        for value in [2000, 0, -500, 1000]
    ]
    ordered = sort_highscores(records, game_mode_id=mode)
    expected = [-500, 1000, 2000, 0] if mode == GameMode.QUESTS else [2000, 1000, 0, -500]
    assert [r.run_elapsed_ms for r in ordered] == expected
    for idx, record in enumerate(ordered):
        assert rank_index([r for r in ordered if r is not record], record) == idx
        assert rank_index(ordered, record) == idx + 1


@pytest.mark.parametrize("date_mode", [HighScoreDateMode.MONTH, HighScoreDateMode.WEEK, HighScoreDateMode.DAY])
def test_date_tables_filter_before_cap_and_save_preserves_history(tmp_path: Path, date_mode: HighScoreDateMode) -> None:
    today = dt.date(2026, 9, 6)
    old = HighScoreRecord(game_mode_id=GameMode.SURVIVAL, score_xp=1000, date=dt.date(2025, 1, 1))
    recent = HighScoreRecord(game_mode_id=GameMode.SURVIVAL, score_xp=10, date=today)
    append_highscore_records(tmp_path, [old] * 105 + [recent])
    assert len(read_highscore_table(tmp_path, SURVIVAL)) == 100
    table = read_highscore_table(tmp_path, SURVIVAL, date_mode=date_mode, now=today)
    assert [r.score_xp for r in table] == [10]
    candidate = HighScoreRecord(game_mode_id=GameMode.SURVIVAL, score_xp=20)
    updated, idx = upsert_highscore_record(tmp_path, SURVIVAL, candidate, date_mode=date_mode, now=today)
    assert idx == 0
    assert [r.score_xp for r in updated] == [20, 10]
    assert len(read_highscore_records(tmp_path)) == 107
    assert read_highscore_table(tmp_path, SURVIVAL, date_mode=date_mode, now=today) == updated


def test_negative_quest_final_time_survives_saving_and_loading(tmp_path: Path) -> None:
    table = ScoreTable(GameMode.QUESTS, quest_level=QuestLevel(1, 1))
    upsert_highscore_record(tmp_path, table, HighScoreRecord(game_mode_id=GameMode.QUESTS, run_elapsed_ms=-500))
    assert read_highscore_table(tmp_path, table)[0].run_elapsed_ms == -500


def test_tables_keep_teams_lists_and_hardcore_quests_apart(tmp_path: Path) -> None:
    level = QuestLevel(2, 7)
    tables = [
        SURVIVAL,
        ScoreTable(GameMode.SURVIVAL, player_count=2),
        ScoreTable(GameMode.SURVIVAL, score_list="Bob"),
        ScoreTable(GameMode.QUESTS, quest_level=level),
        ScoreTable(GameMode.QUESTS, quest_level=level, hardcore=True),
    ]
    for xp, table in enumerate(tables, start=1):
        record = HighScoreRecord(
            game_mode_id=table.game_mode_id, quest_level=table.quest_level, hardcore=table.hardcore, score_xp=xp,
        )
        upsert_highscore_record(tmp_path, table, record)
    # A hardcore Survival run shares the Survival table, as in the original.
    upsert_highscore_record(tmp_path, SURVIVAL, HighScoreRecord(game_mode_id=GameMode.SURVIVAL, hardcore=True, score_xp=9))

    assert [[r.score_xp for r in read_highscore_table(tmp_path, table)] for table in tables] == [[9, 1], [2], [3], [4], [5]]


def test_a_torn_last_line_is_skipped_and_the_next_record_survives(tmp_path: Path) -> None:
    append_highscore_records(tmp_path, [HighScoreRecord(name="first")])
    with scores_path(tmp_path).open("ab") as fp:
        fp.write(b'{"v":1,"name":"tor')
    append_highscore_records(tmp_path, [HighScoreRecord(name="second")])
    assert [r.name for r in read_highscore_records(tmp_path)] == ["first", "second"]


def test_records_round_trip_with_their_replay_link(tmp_path: Path) -> None:
    record = HighScoreRecord(
        name="Ädelé",
        game_mode_id=GameMode.QUESTS,
        quest_level=QuestLevel(5, 10),
        hardcore=True,
        player_count=2,
        score_list="Bob",
        run_elapsed_ms=-1,
        score_xp=0xFFFFFFFF,
        uni_num=12345,
        date=dt.date(2026, 10, 22),
        replay_number=7,
        run="a" * 64,
        rules=2,
        game_version="0.20.0",
    )
    append_highscore_records(tmp_path, [record])
    assert read_highscore_records(tmp_path) == [record]


def test_append_does_not_require_unix_pread(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "pread", raising=False)
    for name in ("first", "second"):
        append_highscore_records(tmp_path, [HighScoreRecord(name=name)])
    assert [r.name for r in read_highscore_records(tmp_path)] == ["first", "second"]


def test_short_writes_are_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: write(fd, data[:7]))
    records = [HighScoreRecord(name="first"), HighScoreRecord(name="second")]
    append_highscore_records(tmp_path, records)
    assert read_highscore_records(tmp_path) == records


@pytest.mark.parametrize("failure", ["zero", "write", "fsync"])
def test_failed_append_rolls_back_and_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    first = HighScoreRecord(name="first")
    second = HighScoreRecord(name="second")
    append_highscore_records(tmp_path, [first])
    before = scores_path(tmp_path).read_bytes()
    write = os.write
    calls = 0

    def broken_write(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return write(fd, data[:7])
        if failure == "zero":
            return 0
        raise OSError("injected disk full")

    def broken_sync(fd):
        raise OSError("injected flush failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", broken_sync) if failure == "fsync" else patch.setattr(os, "write", broken_write)
        with pytest.raises(OSError):
            append_highscore_records(tmp_path, [second])
    assert scores_path(tmp_path).read_bytes() == before
    append_highscore_records(tmp_path, [second])
    assert read_highscore_records(tmp_path) == [first, second]


def test_concurrent_partial_appends_do_not_interleave(tmp_path: Path) -> None:
    scores_path(tmp_path).write_bytes(b'{"v":1,"name":"torn')
    script = """
import os, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from crimson.persistence.highscores import HighScoreRecord, append_highscore_records
write = os.write
def partial(fd, data):
    time.sleep(0.001)
    return write(fd, data[:7])
os.write = partial
for i in range(10):
    append_highscore_records(Path(sys.argv[2]), [HighScoreRecord(name=f'{sys.argv[3]}-{i}')])
"""
    source = Path(__file__).resolve().parents[2] / "src"
    children = [subprocess.Popen([sys.executable, "-c", script, str(source), str(tmp_path), str(i)]) for i in range(3)]
    for child in children:
        assert child.wait(timeout=30) == 0
    assert {r.name for r in read_highscore_records(tmp_path)} == {f"{i}-{j}" for i in range(3) for j in range(10)}
