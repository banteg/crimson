from __future__ import annotations

import msgspec

from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ..panels.hit_test import mouse_inside_rect_with_padding


class DropdownResult(msgspec.Struct, frozen=True):
    is_open: bool
    selected_index: int | None = None
    consumed: bool = False


def dropdown_update(
    *,
    layout,
    item_count: int,
    is_open: bool,
    enabled: bool,
    scale: float,
) -> DropdownResult:
    mouse = rl.get_mouse_position()
    click = bool(enabled) and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
    hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
        mouse,
        pos=layout.pos,
        width=layout.width,
        height=14.0 * float(scale),
    )
    if hovered_header and click:
        return DropdownResult(is_open=not bool(is_open), consumed=True)
    if not bool(is_open):
        return DropdownResult(is_open=bool(is_open), consumed=False)

    list_hovered = Rect.from_top_left(layout.pos, layout.width, layout.full_h).contains(Vec2.from_xy(mouse))
    if click and not list_hovered:
        return DropdownResult(is_open=False, consumed=True)

    for idx in range(int(item_count)):
        item_y = layout.rows_y0 + layout.row_h * float(idx)
        hovered = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=Vec2(layout.pos.x, item_y),
            width=layout.width,
            height=14.0 * float(scale),
        )
        if hovered and click:
            return DropdownResult(is_open=False, selected_index=idx, consumed=True)

    return DropdownResult(is_open=bool(is_open), consumed=False)


def list_window(*, count: int, visible_rows: int, scroll_index: int) -> tuple[int, int, int]:
    max_scroll = max(0, int(count) - int(visible_rows))
    start = max(0, min(max_scroll, int(scroll_index)))
    end = min(int(count), start + int(visible_rows))
    return start, end, max_scroll


def scrollbar_update(
    *,
    mouse: rl.Vector2,
    click: bool,
    down: bool,
    track_x: float,
    track_y: float,
    track_h: float,
    thumb_top: float,
    thumb_h: float,
    scroll_span: int,
    scale: float,
    scroll_index: int,
    drag_active: bool,
    drag_offset: float,
) -> tuple[int, bool, float]:
    in_track = track_x <= mouse.x < track_x + 10.0 * float(scale) and track_y <= mouse.y < track_y + track_h
    thumb_x = track_x + 1.0 * float(scale)
    thumb_w = 8.0 * float(scale)
    in_thumb = thumb_x <= mouse.x < thumb_x + thumb_w and thumb_top <= mouse.y < thumb_top + thumb_h + 1.0 * float(scale)
    next_scroll = int(scroll_index)
    next_drag_active = bool(drag_active)
    next_drag_offset = float(drag_offset)

    if click and in_track:
        if in_thumb:
            next_drag_active = True
            next_drag_offset = float(mouse.y - thumb_top)
        else:
            travel = max(1.0, track_h - 3.0 * float(scale) - thumb_h)
            target = float(mouse.y - track_y - 1.0 * float(scale) - thumb_h * 0.5)
            target = max(0.0, min(travel, target))
            next_scroll = int(round((target / travel) * float(scroll_span)))
            next_drag_active = True
            next_drag_offset = thumb_h * 0.5

    if next_drag_active:
        if down:
            travel = max(1.0, track_h - 3.0 * float(scale) - thumb_h)
            target = float(mouse.y - track_y - 1.0 * float(scale) - next_drag_offset)
            target = max(0.0, min(travel, target))
            next_scroll = int(round((target / travel) * float(scroll_span)))
        else:
            next_drag_active = False

    return next_scroll, next_drag_active, next_drag_offset
