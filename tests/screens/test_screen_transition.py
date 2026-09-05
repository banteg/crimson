from __future__ import annotations

import pytest

from crimson.screens.actions import Route
from crimson.screens.transitions import ScreenTransition
from crimson.ui.animation import ui_element_anim


@pytest.mark.parametrize("duration", [300, 900])
def test_close_crosses_zero_once_and_resume_restarts_only_animation(duration) -> None:
    transition = ScreenTransition(duration)
    transition.advance(duration + 50)
    assert transition.timeline_ms == duration
    transition.begin(Route.BACK)
    transition.begin(Route.MENU)
    assert not transition.advance(duration)
    assert transition.take_action() is None  # zero is still the last visible frame
    assert not transition.advance(1)
    assert transition.take_action() is Route.BACK
    assert transition.take_action() is None
    transition.advance(100)
    assert transition.timeline_ms == -1
    transition.reset()
    assert transition.advance(16)
    assert transition.timeline_ms == 16
    assert transition.duration_ms == duration


@pytest.mark.parametrize(("timeline", "expected"), [(0, -510), (100, -510), (250, -255), (400, 0), (500, 0)])
def test_quest_results_keeps_100ms_hold_then_300ms_slide(timeline, expected) -> None:
    _, slide = ui_element_anim(timeline, index=1, start_ms=400, end_ms=100, width=510)
    assert slide == expected


def test_panels_and_sign_keep_opposite_directions_and_staggered_intervals() -> None:
    angle, left = ui_element_anim(150, index=1, start_ms=300, end_ms=0, width=510)
    sign_angle, right = ui_element_anim(150, index=0, start_ms=300, end_ms=0, width=510, direction_flag=1)
    assert left == -255
    assert right == 255
    assert sign_angle == -angle == -0.7853982
    # A later main-menu item is still hidden while the panel is halfway in.
    assert ui_element_anim(150, index=3, start_ms=600, end_ms=300, width=510) == (1.5707964, -510)
