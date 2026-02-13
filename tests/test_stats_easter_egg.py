from __future__ import annotations

import datetime as dt
import random

from crimson.frontend.panels.stats import (
    _is_orbes_volantes_day,
    _stats_menu_easter_roll,
)


def test_stats_menu_easter_roll_keeps_existing_value() -> None:
    rng = random.Random(123)
    assert _stats_menu_easter_roll(7, rng=rng) == 7


def test_stats_menu_easter_roll_generates_0_to_31_when_unset() -> None:
    rng = random.Random(123)
    roll = _stats_menu_easter_roll(-1, rng=rng)
    assert 0 <= roll < 32


def test_is_orbes_volantes_day_requires_march_third() -> None:
    assert _is_orbes_volantes_day(dt.date(2026, 3, 3)) is True
    assert _is_orbes_volantes_day(dt.date(2026, 3, 2)) is False
    assert _is_orbes_volantes_day(dt.date(2026, 4, 3)) is False
