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
