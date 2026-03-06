from __future__ import annotations

import pytest

from crimson.screens.panels.controls import (
    _controls_left_panel_pos_x,
    _controls_right_panel_pos_x,
    _controls_right_panel_pos_y,
)


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, 286.0),
        (800, 366.0),
        (960, 526.0),
        (1024, 590.0),
        (1280, 846.0),
    ),
)
def test_controls_right_panel_pos_x_matches_capture_formula(screen_width: int, expected: float) -> None:
    assert _controls_right_panel_pos_x(float(screen_width)) == expected


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, 96.0),
        (800, 110.0),
        (1024, 110.0),
    ),
)
def test_controls_right_panel_pos_y_small_width_branch(screen_width: int, expected: float) -> None:
    assert _controls_right_panel_pos_y(float(screen_width)) == expected


@pytest.mark.parametrize(
    ("screen_width", "expected"),
    (
        (640, -183.0),
        (800, -165.0),
        (1024, -165.0),
    ),
)
def test_controls_left_panel_pos_x_small_width_branch(screen_width: int, expected: float) -> None:
    assert _controls_left_panel_pos_x(float(screen_width)) == expected
