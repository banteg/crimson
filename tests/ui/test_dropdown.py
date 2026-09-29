from __future__ import annotations

import pytest

from crimson.ui.dropdown import UiListWidget, ui_list_widget_update
from crimson.ui.focus import UiFocus
from grim.fonts.small import measure_small_text_width
from grim.geom import Vec2

POS = Vec2(100.0, 200.0)
ITEMS = ("Quests", "Rush", "Survival", "Typ'o'Shooter")


def test_width_is_the_widest_item_plus_48(headless_resources) -> None:
    focus = UiFocus()
    widget = UiListWidget(items=ITEMS)
    width = measure_small_text_width(headless_resources.small_font, "Typ'o'Shooter") + 48.0

    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(width - 0.5, 5.0), click=False, preserve_bugs=False) == -1
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(width, 5.0), click=False, preserve_bugs=False) == -2
    widget.items = ITEMS[:3]
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(width - 0.5, 5.0), click=False, preserve_bugs=False) == -2


def test_header_returns_minus_one_and_an_open_list_returns_the_row_under_the_mouse(headless_resources) -> None:
    focus = UiFocus()
    widget = UiListWidget(items=ITEMS)

    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=Vec2(-1000.0, -1000.0), click=False, preserve_bugs=False) == -2
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 5.0), click=False, preserve_bugs=False) == -1
    assert not widget.hovered

    widget.open = True
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 16.0 * 3 + 5.0), click=False, preserve_bugs=False) == 2
    assert widget.hovered
    # Off the rows but inside the list, the last hovered row stays active.
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 5.0), click=False, preserve_bugs=False) == 2
    assert widget.open


def test_open_list_closes_once_the_mouse_leaves_it(headless_resources) -> None:
    focus = UiFocus()
    widget = UiListWidget(items=ITEMS, open=True, active_index=1)

    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 16.0 * 4 + 24.0), click=False, preserve_bugs=False) == 1
    assert not widget.open
    assert not widget.hovered
    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 16.0 * 2 + 5.0), click=False, preserve_bugs=False) == -2


def test_disabled_list_is_forced_closed_and_ignores_the_mouse(headless_resources) -> None:
    focus = UiFocus()
    widget = UiListWidget(items=ITEMS, enabled=False, open=True)

    assert ui_list_widget_update(headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 5.0), click=False, preserve_bugs=False) == -2
    assert not widget.open
    assert not widget.hovered


@pytest.mark.parametrize(("preserve_bugs", "expected"), [(False, -1), (True, 1)])
def test_a_click_outside_an_open_focused_list_closes_it_without_a_row_unless_preserving_bugs(
    headless_resources, preserve_bugs: bool, expected: int,
) -> None:
    focus = UiFocus()
    widget = UiListWidget(items=ITEMS, open=True)
    # Hovering row 1 focuses the list, so it stays open once the mouse leaves.
    ui_list_widget_update(
        headless_resources, widget, POS, focus=focus, mouse=POS + Vec2(5.0, 16.0 * 2 + 5.0), click=False, preserve_bugs=False,
    )
    focus.begin_frame(0)
    outside = Vec2(-1000.0, -1000.0)

    assert ui_list_widget_update(
        headless_resources, widget, POS, focus=focus, mouse=outside, click=True, preserve_bugs=preserve_bugs,
    ) == expected
