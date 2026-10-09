from __future__ import annotations

import pytest

from crimson.ui.formatting import format_ordinal, format_time_mm_ss, highscore_format_date_label


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "1st"),
        (2, "2nd"),
        (3, "3rd"),
        (4, "4th"),
        (11, "11th"),
        (21, "21st"),
        # Native only special-cases 8..20, so the hundreds keep st/nd/rd.
        (111, "111st"),
    ],
)
def test_format_ordinal(value: int, expected: str) -> None:
    assert format_ordinal(value) == expected


@pytest.mark.parametrize(
    ("ms", "expected"),
    [
        (-1, "-0:00"),
        (-61_500, "-1:01"),
        (999, "0:00"),
        (60_000, "1:00"),
        (3_661_000, "61:01"),
    ],
)
def test_format_time_mm_ss(ms: int, expected: str) -> None:
    assert format_time_mm_ss(ms) == expected



def test_highscore_date_label_marks_unknown_months() -> None:
    assert highscore_format_date_label(31, 1, 2026) == "31. Jan 2026"
    assert highscore_format_date_label(0, 0, 2000) == "0. ??? 2000"
