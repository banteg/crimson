from __future__ import annotations

import pytest

from crimson.frontend.high_scores_layout import (
    hs_left_panel_pos_x,
    hs_right_local_card_x_shift,
    hs_right_options_x_shift,
    hs_right_panel_pos_x,
    perks_db_right_detail_x_shift,
    weapons_db_right_detail_x_shift,
)


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, 300.0),
        (800, 420.0),
        (1024, 609.0),
        (1280, 865.0),
        (1366, 951.0),
        (1440, 1025.0),
        (1600, 1185.0),
        (1920, 1505.0),
    ),
)
def test_hs_right_panel_pos_x_matches_classic_formula(screen_width: int, expected: float) -> None:
    assert hs_right_panel_pos_x(float(screen_width)) == expected


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, -169.0),
        (800, -119.0),
        (1024, -119.0),
    ),
)
def test_hs_left_panel_pos_x_small_width_branch(screen_width: int, expected: float) -> None:
    assert hs_left_panel_pos_x(float(screen_width)) == expected


def test_small_width_right_panel_shifts_match_native_callbacks() -> None:
    assert hs_right_options_x_shift(640.0) == 10.0
    assert hs_right_local_card_x_shift(640.0) == 12.0
    assert weapons_db_right_detail_x_shift(640.0) == 20.0
    assert perks_db_right_detail_x_shift(640.0) == -10.0

    assert hs_right_options_x_shift(800.0) == 0.0
    assert hs_right_local_card_x_shift(800.0) == 0.0
    assert weapons_db_right_detail_x_shift(800.0) == 0.0
    assert perks_db_right_detail_x_shift(800.0) == 0.0
