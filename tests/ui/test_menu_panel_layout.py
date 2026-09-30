from __future__ import annotations

import pytest

from crimson.ui.menu_panel import ui_panel_rect
from grim.geom import Vec2


@pytest.mark.parametrize(
    ("index", "width", "top_left", "height"),
    [
        # Slot 9 (scores, databases, credits) steps 50 left at <= 640; its rows move down with the width.
        (9, 640, Vec2(-148.0, 104.0), 378.0),
        (9, 1024, Vec2(-98.0, 194.0), 378.0),
        # The play game panel is the shorter tall copy.
        (11, 1024, Vec2(-108.0, 219.0), 278.0),
        # Slot 33 tracks the right edge.
        (33, 800, Vec2(441.0, 156.5), 254.0),
        (33, 1024, Vec2(630.0, 209.0), 254.0),
        # Slot 40 (the controls' bindings) is placed after the widescreen shift.
        (40, 640, Vec2(307.0, 105.0), 378.0),
        (40, 800, Vec2(387.0, 119.0), 378.0),
    ],
)
def test_ui_panel_rect_places_panels_at_native_element_positions(
    index: int, width: int, top_left: Vec2, height: float,
) -> None:
    rect = ui_panel_rect(index, 1000.0, width)
    assert (rect.top_left, rect.width, rect.height) == (top_left, 510.0, height)


def test_right_hand_panels_slide_in_from_the_right() -> None:
    settled = ui_panel_rect(33, 1000.0, 1024)
    assert ui_panel_rect(33, 150.0, 1024).left == settled.left + 255.0
    assert ui_panel_rect(9, 150.0, 1024).left == ui_panel_rect(9, 1000.0, 1024).left - 255.0
