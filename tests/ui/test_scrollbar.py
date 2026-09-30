from __future__ import annotations

import pytest

from crimson.ui.focus import UiFocus
from crimson.ui.scrollbar import UiScrollbar, ui_scrollbar_update
from grim.geom import Vec2

POS = Vec2(100.0, 200.0)
# Ten 16px rows plus the 2px frame and a 2px gap.
HEIGHT = 164.0
TRACK_X = POS.x + 245.0


def bar(count: int = 30) -> UiScrollbar:
    return UiScrollbar(items=[f"item {i}" for i in range(count)], visible_rows=10)


def update(
    focus: UiFocus, scrollbar: UiScrollbar, mouse: Vec2, *, click: bool = False, down: bool = False, wheel: float = 0.0,
) -> None:
    ui_scrollbar_update(focus, scrollbar, POS, mouse=mouse, click=click, down=down, wheel=wheel)


def test_a_press_on_the_thumb_keeps_its_grab_point_while_dragging() -> None:
    focus = UiFocus()
    scrollbar = bar()
    # Thirty items in ten rows: the 54px thumb starts a pixel into the track.
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 20.0), click=True, down=True)
    assert scrollbar.drag_active
    assert scrollbar.drag_offset == 20.0
    assert scrollbar.scroll_offset == 0.0

    # The item count maps onto the frame's full height.
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 20.0 + HEIGHT / 30.0 * 6.0), down=True)
    assert scrollbar.scroll_offset == pytest.approx(6.0)


def test_a_press_on_the_track_off_the_thumb_grabs_the_thumb_top() -> None:
    focus = UiFocus()
    scrollbar = bar()
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 82.0), click=True, down=True)
    assert scrollbar.drag_offset == 0.0
    assert scrollbar.scroll_offset == pytest.approx(82.0 / HEIGHT * 30.0)

    # Past the bottom it stops at the last page.
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 160.0), down=True)
    assert scrollbar.scroll_offset == 20.0


def test_the_drag_follows_the_mouse_off_the_track_until_released() -> None:
    focus = UiFocus()
    scrollbar = bar()
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 10.0), click=True, down=True)
    update(focus, scrollbar, Vec2(TRACK_X + 200.0, POS.y + 10.0 + HEIGHT / 30.0 * 4.0), down=True)
    assert scrollbar.drag_active
    assert scrollbar.scroll_offset == pytest.approx(4.0)

    update(focus, scrollbar, Vec2(TRACK_X + 200.0, POS.y + 100.0))
    assert not scrollbar.drag_active
    update(focus, scrollbar, Vec2(TRACK_X + 200.0, POS.y + 150.0), down=True)
    assert scrollbar.scroll_offset == pytest.approx(4.0)


def test_a_list_that_fits_has_no_track() -> None:
    focus = UiFocus()
    scrollbar = bar(count=10)
    update(focus, scrollbar, Vec2(TRACK_X, POS.y + 80.0), click=True, down=True)
    assert not scrollbar.drag_active
    assert scrollbar.scroll_offset == 0.0


def test_the_row_under_the_mouse_is_hovered_and_a_click_selects_it() -> None:
    focus = UiFocus()
    scrollbar = bar()
    scrollbar.scroll_offset = 5.0
    update(focus, scrollbar, Vec2(POS.x + 50.0, POS.y + 16.0 * 3 + 8.0))
    assert scrollbar.hovered_index == 8
    assert scrollbar.selected_index == 0

    update(focus, scrollbar, Vec2(POS.x + 50.0, POS.y + 16.0 * 3 + 8.0), click=True, down=True)
    assert scrollbar.selected_index == 8


@pytest.mark.parametrize(
    ("dx", "dy", "expected"),
    [
        # Rows are 17px tall, so the pixel a row overlaps the next belongs to the lower one.
        (50.0, 16.5, 1),
        (50.0, 16.0, 0),
        # Hot from 2px left of the frame, 240px wide: the scrollbar track is not a row.
        (-1.5, 8.0, 0),
        (-2.0, 8.0, -1),
        (237.5, 8.0, 0),
        (238.0, 8.0, -1),
    ],
)
def test_row_hit_edges(dx: float, dy: float, expected: int) -> None:
    focus = UiFocus()
    scrollbar = bar()
    update(focus, scrollbar, Vec2(POS.x + dx, POS.y + dy))
    assert scrollbar.hovered_index == expected


def test_the_wheel_scrolls_a_row_without_the_focus_and_stops_at_the_ends() -> None:
    focus = UiFocus()
    scrollbar = bar()
    outside = Vec2(-100.0, -100.0)
    update(focus, scrollbar, outside, wheel=-0.25)
    assert scrollbar.scroll_offset == 1.0
    update(focus, scrollbar, outside, wheel=3.0)
    update(focus, scrollbar, outside, wheel=3.0)
    assert scrollbar.scroll_offset == 0.0

    focus.page_down = True
    for _ in range(4):
        update(focus, scrollbar, outside)
    assert scrollbar.scroll_offset == 20.0
