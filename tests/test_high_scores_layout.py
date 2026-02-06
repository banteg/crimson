from __future__ import annotations

import pytest

from crimson.frontend.high_scores_layout import hs_right_panel_pos_x


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, 300.0),
        (800, 420.0),
        (1024, 609.0),
        (1366, 865.0),
        (1440, 865.0),
        (1600, 1185.0),
        (1920, 1505.0),
    ),
)
def test_hs_right_panel_pos_x_matches_classic_formula(screen_width: int, expected: float) -> None:
    assert hs_right_panel_pos_x(float(screen_width)) == expected
