from __future__ import annotations

from crimson.screens.high_scores_layout import (
    hs_right_local_card_x_shift,
    hs_right_options_x_shift,
    perks_db_right_detail_x_shift,
    weapons_db_right_detail_x_shift,
)


def test_small_width_right_panel_shifts_match_native_callbacks() -> None:
    assert hs_right_options_x_shift(640.0) == 10.0
    assert hs_right_local_card_x_shift(640.0) == 12.0
    assert weapons_db_right_detail_x_shift(640.0) == 20.0
    assert perks_db_right_detail_x_shift(640.0) == -10.0

    assert hs_right_options_x_shift(800.0) == 0.0
    assert hs_right_local_card_x_shift(800.0) == 0.0
    assert weapons_db_right_detail_x_shift(800.0) == 0.0
    assert perks_db_right_detail_x_shift(800.0) == 0.0
