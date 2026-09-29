from __future__ import annotations

import pytest

from crimson.screens.actions import Route
from crimson.screens.ui_timeline import UiTimeline
from crimson.ui.animation import ui_element_anim


@pytest.mark.parametrize("max_timeline", [300, 900])
def test_close_crosses_zero_once_and_reentering_rewinds(max_timeline) -> None:
    timeline = UiTimeline()
    timeline.enter(max_timeline)
    timeline.advance(max_timeline + 50)
    assert timeline.timeline_ms == max_timeline
    assert timeline.opened
    timeline.begin(Route.BACK)
    timeline.begin(Route.MENU)
    assert not timeline.advance(max_timeline)
    assert timeline.take_action() is None  # zero is still the last visible frame
    assert not timeline.advance(1)
    assert timeline.take_action() is Route.BACK
    assert timeline.take_action() is None
    timeline.advance(100)
    assert timeline.timeline_ms == -1
    timeline.enter(max_timeline)
    assert timeline.advance(16)
    assert timeline.timeline_ms == 16
    assert timeline.max_timeline_ms == max_timeline


@pytest.mark.parametrize(("timeline", "expected"), [(0, -510), (100, -510), (250, -255), (400, 0), (500, 0)])
def test_quest_results_keeps_100ms_hold_then_300ms_slide(timeline, expected) -> None:
    _, slide = ui_element_anim(timeline, index=35, width=510)
    assert slide == expected


def test_panels_and_sign_keep_opposite_directions_and_staggered_intervals() -> None:
    angle, left = ui_element_anim(150, index=11, width=510)
    sign_angle, right = ui_element_anim(150, index=0, width=510, direction_flag=1)
    assert left == -255
    assert right == 255
    assert sign_angle == -angle == -0.7853982
    # A later main-menu item is still hidden while the panel is halfway in.
    assert ui_element_anim(150, index=3, width=510) == (1.5707964, -510)


def test_pause_items_slide_in_100ms_apart_from_100ms() -> None:
    # `ui_menu_layout_init` shifts pause elements 23..25 by 100/200/300 ms, not the main-menu stagger.
    assert [ui_element_anim(250, index=index, width=300)[1] for index in (23, 24, 25)] == [-150.0, -250.0, -300.0]
