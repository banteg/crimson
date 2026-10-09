from __future__ import annotations

import datetime as dt

from crimson.persistence.highscores import HighScoreRecord, highscore_date_week


def test_blank_highscore_record_initializes_native_uni_num_from_rand_value() -> None:
    record = HighScoreRecord.blank(rand_value=0x7FFF)

    assert record.uni_num == 0x50F
    assert record.reserved == 0


def test_ensure_date_fields_sets_native_date_week_byte() -> None:
    record = HighScoreRecord.blank(rand_value=0)
    record.ensure_date_fields(dt.date(2026, 5, 28))

    assert record.date_week == highscore_date_week(2026, 5, 28)


import shutil
import subprocess
from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.persistence.highscores import (
    rank_index,
    read_highscore_records,
    read_highscore_table,
    sort_highscores,
    upsert_highscore_record,
    write_highscore_records,
)
from grim.config import HighScoreDateMode


@pytest.mark.parametrize("name, expected", [("Player  ", "Player"), ("   ", " "), ("", "")])
def test_saved_names_trim_in_place_with_native_first_character_rule(tmp_path: Path, name: str, expected: str) -> None:
    record = HighScoreRecord.blank(rand_value=0)
    record.set_name(name)
    path = tmp_path / "scores.hi"
    write_highscore_records(path, [record])
    assert read_highscore_records(path)[0].name() == expected
    assert record.name() == name


@pytest.mark.parametrize("mode", [GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS])
def test_signed_ranking_matches_sorted_order_including_empty_quest_times(mode: GameMode) -> None:
    records = []
    for value in [2000, 0, -500, 1000]:
        record = HighScoreRecord.blank(rand_value=0)
        record.game_mode_id = mode
        record.run_elapsed_ms = value
        record.score_xp = value
        records.append(record)
    ordered = sort_highscores(records, game_mode_id=mode)
    expected = [-500, 1000, 2000, 0] if mode == GameMode.QUESTS else [2000, 1000, 0, -500]
    assert [r.score_xp for r in ordered] == [value & 0xFFFFFFFF for value in expected]
    for idx, record in enumerate(ordered):
        assert rank_index([r for r in ordered if r is not record], record) == idx
        assert rank_index(ordered, record) == idx + 1


@pytest.mark.parametrize("date_mode", [HighScoreDateMode.MONTH, HighScoreDateMode.WEEK, HighScoreDateMode.DAY])
def test_date_tables_filter_before_cap_and_save_preserves_history(tmp_path: Path, date_mode: HighScoreDateMode) -> None:
    path = tmp_path / "survival.hi"
    today = dt.date(2026, 9, 6)
    old = HighScoreRecord.blank(rand_value=0)
    old.game_mode_id = GameMode.SURVIVAL
    old.score_xp = 1000
    old.ensure_date_fields(dt.date(2025, 1, 1))
    recent = HighScoreRecord.blank(rand_value=1)
    recent.game_mode_id = GameMode.SURVIVAL
    recent.score_xp = 10
    recent.ensure_date_fields(today)
    write_highscore_records(path, [old] * 105 + [recent])
    assert len(read_highscore_table(path, game_mode_id=GameMode.SURVIVAL)) == 100
    table = read_highscore_table(path, game_mode_id=GameMode.SURVIVAL, date_mode=date_mode, now=today)
    assert [r.score_xp for r in table] == [10]
    candidate = HighScoreRecord.blank(rand_value=2)
    candidate.game_mode_id = GameMode.SURVIVAL
    candidate.score_xp = 20
    updated, idx = upsert_highscore_record(path, candidate, date_mode=date_mode, now=today)
    assert idx == 0
    assert [r.score_xp for r in updated] == [20, 10]
    assert len(read_highscore_records(path)) == 107
    assert read_highscore_table(path, game_mode_id=GameMode.SURVIVAL, date_mode=date_mode, now=today) == updated


def test_negative_quest_final_time_survives_saving_and_loading(tmp_path: Path) -> None:
    path = tmp_path / "quest.hi"
    record = HighScoreRecord.blank(rand_value=0)
    record.game_mode_id = GameMode.QUESTS
    record.run_elapsed_ms = -500
    upsert_highscore_record(path, record)
    assert read_highscore_table(path, game_mode_id=GameMode.QUESTS)[0].run_elapsed_ms == -500


@pytest.fixture(scope="module")
def original_record_io(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = Path(__file__).resolve().parents[2]
    # Clang, as the recovered sources build: the stub headers' WINAPI is __stdcall, which GCC rejects.
    cc = shutil.which("clang")
    assert cc is not None
    exe = tmp_path_factory.mktemp("highscore") / "highscore_record_harness"
    subprocess.run(
        [
            cc,
            "-w",
            "-fsigned-char",  # MSVC x86 char
            f"-I{root / 'crimson-core/game/include'}",
            f"-I{root / 'tools/match/include'}",
            f"-I{root / 'third_party/headers'}",
            str(Path(__file__).with_name("highscore_record_harness.c")),
            str(root / "decomp/1.9/crimsonland/highscore/highscore_read_record.c"),
            str(root / "decomp/1.9/crimsonland/highscore/highscore_write_record.c"),
            "-o",
            str(exe),
        ],
        check=True,
    )
    return exe


def test_score_files_round_trip_with_the_original_record_io(tmp_path: Path, original_record_io: Path) -> None:
    records = []
    for name, mode, elapsed_ms, score in [
        ("Player", GameMode.SURVIVAL, 754_321, 98_765),
        ("\xc4\xe9\xff", GameMode.RUSH, 61_000, 0),
        ("Quester", GameMode.QUESTS, -500, 0x8000_0000),
    ]:
        record = HighScoreRecord.blank(rand_value=0x7FFF)
        record.set_name(name)
        record.game_mode_id = mode
        record.run_elapsed_ms = elapsed_ms
        record.score_xp = score
        record.ensure_date_fields(dt.date(2026, 10, 9))
        records.append(record)
    path = tmp_path / "scores.hi"

    write_highscore_records(path, records)
    loaded = subprocess.run([original_record_io, "read"], input=path.read_bytes(), capture_output=True, check=True)
    assert loaded.stdout == b"".join(bytes(r.data) for r in records)

    written = subprocess.run([original_record_io, "write"], input=loaded.stdout, capture_output=True, check=True)
    path.write_bytes(written.stdout)
    assert read_highscore_records(path) == records
