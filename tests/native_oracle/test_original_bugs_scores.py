"""GOG 1.9.93 score and Statistics menu regressions for original bugs 74 through 76."""

from __future__ import annotations

import datetime as dt
import io
import struct

import pytest

from crimson.game_modes import GameMode
from crimson.game_states import GameStateId
from grim.config import HighScoreDateMode


@pytest.fixture
def score_file(oracle) -> int:
    """Serve a scores5 file in memory while the executable encodes, decodes and sorts it."""
    stream = io.BytesIO()
    fp = oracle.alloc(32)
    file_flags = fp + 0x0C  # MSVCRT FILE._flag; feof is inlined in the executable.

    def fopen(_call):
        stream.seek(0)
        oracle.write_u32(file_flags, 0)
        return fp

    def fwrite(call):
        src, size, count = (call.arg_u32(i) for i in range(3))
        stream.seek(0, io.SEEK_END)
        return stream.write(oracle.read(src, size * count)) // size

    def fread(call):
        dst, size, count = (call.arg_u32(i) for i in range(3))
        data = stream.read(size * count)
        if data:
            oracle.write(dst, data)
        if len(data) < size * count:
            oracle.write_u32(file_flags, 0x10)
        return len(data) // size

    oracle.stub("highscore_build_path", oracle.alloc(16))
    oracle.stub("crt_fopen", fopen)
    oracle.stub("crt_fclose", 0)
    oracle.stub("crt_fwrite", fwrite)
    oracle.stub("crt_fread", fread)
    # The writer calls GetLocalTime(&local_system_time). Seed that output before each call.
    oracle.stub_import("GetLocalTime", None, pop=4)
    oracle.write_u8("config_highscore_duplicate_mode", 0)
    oracle.write_u8("config_highscore_date_mode", HighScoreDateMode.ALL_TIME)
    oracle.write_u32("config_selected_saved_name_slot", 0)
    return fp


def _set_date(oracle, day: dt.date) -> None:
    oracle.write("local_system_time", struct.pack("<8H", day.year, day.month, 0, day.day, 0, 0, 0, 0))


def _save(oracle, fp: int, name: bytes, score: int, day: dt.date) -> None:
    _set_date(oracle, day)
    ptr = oracle.alloc(0x48)
    mode = oracle.read_u32("config_game_mode")
    oracle.write(ptr, struct.pack("<32siiB", name, 9000, score, mode))
    oracle.write(ptr + 0x46, b"|\xff")
    oracle.call("highscore_write_record", ptr, fp)


def _visible_rows(oracle) -> list[bytes]:
    # From the start of the real row builder to the store of scrollbar.item_count.
    # ESI is the first rank. The scrollbar's static-constructor bit skips its atexit registration.
    oracle.write_u8("highscore_screen_init_flags", 2)
    oracle.run(0x442B4D, 0x442CCD, regs={"esi": 1})
    count = oracle.read_i32(oracle.resolve("highscore_screen_score_scrollbar") + 0x34)
    items = oracle.resolve("highscore_screen_score_line_items")
    return [oracle.read(oracle.read_u32(items + i * 4), 164).split(b"\0", 1)[0] for i in range(count)]


@pytest.mark.parametrize("mode", [GameMode.SURVIVAL, GameMode.TYPO])
def test_zero_score_is_saved_but_invisible(oracle, score_file, mode) -> None:
    oracle.write_u32("config_game_mode", mode)
    day = dt.date(2025, 1, 1)
    _save(oracle, score_file, b"no kills", 0, day)
    oracle.call("highscore_load_table")

    assert oracle.read_i32("highscore_table_count") == 1
    table = oracle.resolve("highscore_table")
    assert oracle.read_u32(table + 0x20) == 0  # The sort placed an empty record first.
    name = oracle.alloc(9, data=b"no kills\0")
    saved = oracle.call("highscore_find_name_entry", name, 100).eax
    assert saved > table
    assert oracle.read_u32(saved + 0x20) == 9000
    assert _visible_rows(oracle) == []

    _save(oracle, score_file, b"positive", 1, day)
    oracle.call("highscore_load_table")
    assert oracle.read_i32("highscore_table_count") == 2
    assert _visible_rows(oracle) == [b"1\t1\tpositive"]


@pytest.mark.parametrize(
    ("mode", "visible_count"),
    [(GameMode.SURVIVAL, 100), (GameMode.RUSH, 100), (GameMode.TYPO, 100), (GameMode.QUESTS, 99)],
)
def test_full_score_table_rank_count_and_visible_count(oracle, score_file, mode, visible_count) -> None:
    oracle.write_u32("config_game_mode", mode)
    oracle.write_u8("config_hardcore", 0)
    for score in range(1, 101):
        _save(oracle, score_file, f"run {score}".encode("ascii"), score, dt.date(2025, 1, 1))
    oracle.call("highscore_load_table")

    assert oracle.read_i32("highscore_table_count") == 99
    # A run beaten by every saved run still qualifies at index 99 in all four modes.
    oracle.write_u32("highscore_score_xp", 0)
    oracle.write_u32("run_elapsed_ms", 10_000 if mode == GameMode.QUESTS else 1)
    assert oracle.call("highscore_rank_index").eax == 99
    assert len(_visible_rows(oracle)) == visible_count


def test_weekly_filter_shows_a_year_old_score_then_hides_yesterdays(oracle, score_file) -> None:
    oracle.write_u32("config_game_mode", GameMode.SURVIVAL)
    jan_1 = dt.date(2025, 1, 1)
    dec_31 = dt.date(2025, 12, 31)
    new_year = dt.date(2026, 1, 1)
    _save(oracle, score_file, b"January", 3, jan_1)
    _save(oracle, score_file, b"December", 2, dec_31)
    oracle.write_u8("config_highscore_date_mode", HighScoreDateMode.WEEK)
    oracle.call("highscore_load_table")
    assert _visible_rows(oracle) == [b"1\t3\tJanuary", b"2\t2\tDecember"]

    _save(oracle, score_file, b"New Year", 1, new_year)
    oracle.call("highscore_load_table")
    assert _visible_rows(oracle) == [b"1\t1\tNew Year"]

    oracle.write_u8("config_highscore_date_mode", HighScoreDateMode.ALL_TIME)
    oracle.call("highscore_load_table")
    assert _visible_rows(oracle) == [b"1\t3\tJanuary", b"2\t2\tDecember", b"3\t1\tNew Year"]


def test_statistics_opens_chapter_four_scores_for_chapter_five(oracle) -> None:
    oracle.write_u32("config_game_mode", GameMode.QUESTS)
    oracle.write_u8("config_hardcore", 0)
    oracle.write_u32("config_player_count", 1)
    oracle.write_u32("config_selected_saved_name_slot", 0)
    oracle.write_u32("cv_verbose", oracle.alloc(32))
    oracle.write_u8("highscore_cwd_cached", 1)
    oracle.write("highscore_cwd_buf", b"C:\\Crimson\0")
    oracle.write_u32("quest_stage_major", 5)
    oracle.write_u32("quest_stage_minor", 7)
    opened = []

    def fopen(call):
        opened.append(oracle.read(call.arg_u32(0), 128).split(b"\0", 1)[0])
        return 0

    oracle.stub("crt_fopen", fopen)
    oracle.call("highscore_load_table")
    assert opened == [b"C:\\Crimson\\scores5\\questhc5_7.hi"]

    # The activated button sets the pending screen and calls the same table loader.
    oracle.write_u8(oracle.resolve("statistics_high_scores_button") + 5, 1)
    oracle.run(0x43FEAE, 0x43FF24, regs={"ebx": 0}, st=(0.0,))
    assert oracle.read_i32("game_state_pending") == GameStateId.HIGHSCORES
    assert (oracle.read_i32("quest_stage_major"), oracle.read_i32("quest_stage_minor")) == (4, 7)
    assert opened[-1] == b"C:\\Crimson\\scores5\\questhc4_7.hi"
