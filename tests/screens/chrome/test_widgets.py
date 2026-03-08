from __future__ import annotations

from types import SimpleNamespace

from crimson.screens.chrome.widgets import dropdown_update, list_window, scrollbar_update
from grim.geom import Vec2
from grim.raylib_api import rl


def test_list_window_clamps_scroll_index() -> None:
    start, end, max_scroll = list_window(count=25, visible_rows=10, scroll_index=99)

    assert start == 15
    assert end == 25
    assert max_scroll == 15


def test_dropdown_update_selects_hovered_item(mocker) -> None:
    layout = SimpleNamespace(
        pos=Vec2(10.0, 10.0),
        width=100.0,
        row_h=16.0,
        rows_y0=27.0,
        full_h=72.0,
    )
    mocker.patch.object(
        rl,
        "get_mouse_position",
        return_value=rl.Vector2(12.0, 44.0),
    )
    mocker.patch.object(
        rl,
        "is_mouse_button_pressed",
        side_effect=lambda button: int(button) == int(rl.MouseButton.MOUSE_BUTTON_LEFT),
    )

    result = dropdown_update(layout=layout, item_count=3, is_open=True, enabled=True, scale=1.0)

    assert result.is_open is False
    assert result.selected_index == 1
    assert result.consumed is True


def test_scrollbar_update_enters_drag_mode_when_thumb_clicked() -> None:
    scroll_index, drag_active, drag_offset = scrollbar_update(
        mouse=rl.Vector2(12.0, 35.0),
        click=True,
        down=True,
        track_x=10.0,
        track_y=10.0,
        track_h=100.0,
        thumb_top=30.0,
        thumb_h=20.0,
        scroll_span=10,
        scale=1.0,
        scroll_index=0,
        drag_active=False,
        drag_offset=0.0,
    )

    assert scroll_index == 2
    assert drag_active is True
    assert drag_offset == 5.0
