from __future__ import annotations

from crimson.ui.dropdown import UiListWidget, ui_list_widget_update
from grim.fonts.small import measure_small_text_width
from grim.geom import Vec2

POS = Vec2(100.0, 200.0)
ITEMS = ("Quests", "Rush", "Survival", "Typ'o'Shooter")


def test_width_is_the_widest_item_plus_48(headless_resources) -> None:
    widget = UiListWidget(items=ITEMS)
    width = measure_small_text_width(headless_resources.small_font, "Typ'o'Shooter") + 48.0

    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(width - 0.5, 5.0)) == -1
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(width, 5.0)) == -2
    widget.items = ITEMS[:3]
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(width - 0.5, 5.0)) == -2


def test_header_returns_minus_one_and_an_open_list_returns_the_row_under_the_mouse(headless_resources) -> None:
    widget = UiListWidget(items=ITEMS)

    assert ui_list_widget_update(headless_resources, widget, POS, mouse=Vec2(-1000.0, -1000.0)) == -2
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 5.0)) == -1
    assert not widget.hovered

    widget.open = True
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 16.0 * 3 + 5.0)) == 2
    assert widget.hovered
    # Off the rows but inside the list, the last hovered row stays active.
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 5.0)) == 2
    assert widget.open


def test_open_list_closes_once_the_mouse_leaves_it(headless_resources) -> None:
    widget = UiListWidget(items=ITEMS, open=True, active_index=1)

    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 16.0 * 4 + 24.0)) == 1
    assert not widget.open
    assert not widget.hovered
    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 16.0 * 2 + 5.0)) == -2


def test_disabled_list_is_forced_closed_and_ignores_the_mouse(headless_resources) -> None:
    widget = UiListWidget(items=ITEMS, enabled=False, open=True)

    assert ui_list_widget_update(headless_resources, widget, POS, mouse=POS + Vec2(5.0, 5.0)) == -2
    assert not widget.open
    assert not widget.hovered
