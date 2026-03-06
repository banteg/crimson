from __future__ import annotations

import pytest

from crimson.ui.formatting import format_ordinal, format_time_mm_ss


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "1st"),
        (2, "2nd"),
        (3, "3rd"),
        (4, "4th"),
        (10, "10th"),
        (11, "11th"),
        (12, "12th"),
        (13, "13th"),
        (14, "14th"),
        (21, "21st"),
        (22, "22nd"),
        (23, "23rd"),
        (24, "24th"),
        (111, "111th"),
        (112, "112th"),
        (113, "113th"),
        (121, "121st"),
        (122, "122nd"),
        (123, "123rd"),
    ],
)
def test_format_ordinal(value: int, expected: str) -> None:
    assert format_ordinal(value) == expected


@pytest.mark.parametrize(
    ("ms", "expected"),
    [
        (-1, "0:00"),
        (0, "0:00"),
        (999, "0:00"),
        (1000, "0:01"),
        (59_000, "0:59"),
        (60_000, "1:00"),
        (61_000, "1:01"),
        (3_661_000, "61:01"),
    ],
)
def test_format_time_mm_ss(ms: int, expected: str) -> None:
    assert format_time_mm_ss(ms) == expected

