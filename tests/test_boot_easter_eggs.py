from __future__ import annotations

import datetime as dt

from crimson.frontend.boot import _is_balloon_easter_egg_day


def test_balloon_easter_egg_day_matches_three_known_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 12)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 11, 8)) is True
    assert _is_balloon_easter_egg_day(dt.date(2026, 12, 18)) is True


def test_balloon_easter_egg_day_rejects_other_dates() -> None:
    assert _is_balloon_easter_egg_day(dt.date(2026, 3, 3)) is False
    assert _is_balloon_easter_egg_day(dt.date(2026, 9, 11)) is False
