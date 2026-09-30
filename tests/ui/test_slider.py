from __future__ import annotations

import pytest

from crimson.ui.focus import UiFocus
from crimson.ui.slider import UiSegmentedSlider, ui_segmented_slider_update
from grim.geom import Vec2

POS = Vec2(300.0, 200.0)


@pytest.mark.parametrize(
    ("dx", "expected"),
    [
        # The value is the 8px segment under the mouse: the first one is 0.
        (1.0, 0),
        (7.9, 0),
        (8.0, 1),
        (59.0, 7),
        (79.0, 9),
        # The 3px margins either side still take the press.
        (-2.5, 0),
        (82.5, 10),
    ],
)
def test_a_held_button_sets_the_segment_under_the_mouse(dx: float, expected: int) -> None:
    slider = UiSegmentedSlider(value=5)
    ui_segmented_slider_update(UiFocus(), slider, POS, mouse=POS + Vec2(dx, 8.0), down=True)
    assert slider.value == expected


def test_min_clamps_the_mouse_value() -> None:
    slider = UiSegmentedSlider(value=3, max=5, min=1)
    ui_segmented_slider_update(UiFocus(), slider, POS, mouse=POS + Vec2(2.0, 8.0), down=True)
    assert slider.value == 1


@pytest.mark.parametrize(
    "offset",
    [Vec2(-3.0, 8.0), Vec2(83.0, 8.0), Vec2(40.0, -1.0), Vec2(40.0, 17.0)],
)
def test_the_mouse_off_the_slider_leaves_it_alone(offset: Vec2) -> None:
    slider = UiSegmentedSlider(value=5)
    ui_segmented_slider_update(UiFocus(), slider, POS, mouse=POS + offset, down=True)
    assert slider.value == 5


def test_a_drag_stops_once_the_mouse_leaves_the_slider() -> None:
    focus = UiFocus()
    slider = UiSegmentedSlider(value=0)
    for dx in (4.0, 20.0, 44.0):
        ui_segmented_slider_update(focus, slider, POS, mouse=POS + Vec2(dx, 8.0), down=True)
    assert slider.value == 5
    ui_segmented_slider_update(focus, slider, POS, mouse=POS + Vec2(74.0, 60.0), down=True)
    ui_segmented_slider_update(focus, slider, POS, mouse=POS + Vec2(104.0, 8.0), down=True)
    assert slider.value == 5


def test_a_disabled_slider_ignores_the_mouse() -> None:
    slider = UiSegmentedSlider(value=5, enabled=False)
    ui_segmented_slider_update(UiFocus(), slider, POS, mouse=POS + Vec2(20.0, 8.0), down=True)
    assert slider.value == 5


def test_hovering_focuses_it_and_the_arrows_step_it_down_to_zero() -> None:
    focus = UiFocus()
    other, slider = object(), UiSegmentedSlider(value=1, max=5, min=1)
    focus.update(other)
    ui_segmented_slider_update(focus, slider, POS, mouse=POS + Vec2(20.0, 8.0), down=False)
    assert slider.value == 1
    assert not slider.focused

    focus.restart = True
    focus.update(other)
    focus.left = True
    ui_segmented_slider_update(focus, slider, POS, mouse=Vec2(), down=False)
    assert slider.focused
    # Native only holds the arrows to 0..max; the caller clamps to `min`.
    assert slider.value == 0

    focus.restart = True
    focus.update(other)
    focus.left, focus.right = False, True
    for _ in range(6):
        ui_segmented_slider_update(focus, slider, POS, mouse=Vec2(), down=False)
    assert slider.value == 5
