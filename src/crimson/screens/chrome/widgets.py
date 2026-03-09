from __future__ import annotations

from collections.abc import Sequence

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...ui.layout import DropdownLayoutBase
from ..panels.hit_test import mouse_inside_rect_with_padding


class DropdownResult(msgspec.Struct, frozen=True):
    is_open: bool
    selected_index: int | None = None
    consumed: bool = False


def dropdown_layout(*, pos: Vec2, width: float, item_count: int, scale: float) -> DropdownLayoutBase:
    return DropdownLayoutBase(
        pos=pos,
        width=float(width),
        header_h=16.0 * float(scale),
        row_h=16.0 * float(scale),
        rows_y0=pos.y + 17.0 * float(scale),
        full_h=(float(item_count) * 16.0 + 24.0) * float(scale),
    )


def autosize_dropdown_layout(
    *,
    pos: Vec2,
    items: Sequence[str],
    font: SmallFontData,
    scale: float,
    extra_width: float = 48.0,
) -> DropdownLayoutBase:
    max_label_w = 0.0
    for label in items:
        max_label_w = max(max_label_w, measure_small_text_width(font, str(label)))
    return dropdown_layout(
        pos=pos,
        width=max_label_w + float(extra_width) * float(scale),
        item_count=len(items),
        scale=scale,
    )


def dropdown_draw(
    *,
    resources: RuntimeResources,
    font: SmallFontData,
    layout: DropdownLayoutBase,
    items: Sequence[str],
    selected_index: int,
    is_open: bool,
    enabled: bool = True,
    scale: float,
) -> None:
    mouse = rl.get_mouse_position()
    hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
        mouse,
        pos=layout.pos,
        width=layout.width,
        height=14.0 * float(scale),
    )
    widget_h = layout.full_h if is_open else layout.header_h
    rl.draw_rectangle(int(layout.pos.x), int(layout.pos.y), int(layout.width), int(widget_h), rl.WHITE)
    rl.draw_rectangle(
        int(layout.pos.x) + 1,
        int(layout.pos.y) + 1,
        max(0, int(layout.width) - 2),
        max(0, int(widget_h) - 2),
        rl.BLACK,
    )

    if (is_open or hovered_header) and enabled:
        rl.draw_rectangle(
            int(layout.pos.x),
            int(layout.pos.y + 15.0 * float(scale)),
            int(layout.width),
            max(1, int(1.0 * float(scale))),
            rl.Color(255, 255, 255, 128),
        )

    arrow_tex = (
        resources.texture(TextureId.UI_DROP_ON)
        if ((is_open or hovered_header) and enabled)
        else resources.texture(TextureId.UI_DROP_OFF)
    )
    arrow_size = 16.0 * float(scale)
    rl.draw_texture_pro(
        arrow_tex,
        rl.Rectangle(0.0, 0.0, float(arrow_tex.width), float(arrow_tex.height)),
        rl.Rectangle(layout.pos.x + layout.width - arrow_size - 1.0 * float(scale), layout.pos.y, arrow_size, arrow_size),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )

    if not items:
        return

    header_pos = layout.pos + Vec2(4.0 * float(scale), 1.0 * float(scale))
    clamped_selected = max(0, min(len(items) - 1, int(selected_index)))
    header_alpha = 242 if ((is_open or hovered_header) and enabled) else 191
    draw_small_text(font, str(items[clamped_selected]), header_pos, rl.Color(255, 255, 255, header_alpha))

    if not is_open:
        return

    for idx, item in enumerate(items):
        item_y = layout.rows_y0 + layout.row_h * float(idx)
        hovered = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=Vec2(layout.pos.x, item_y),
            width=layout.width,
            height=14.0 * float(scale),
        )
        alpha = 153
        if hovered:
            alpha = 242
        if idx == clamped_selected:
            alpha = max(alpha, 245)
        draw_small_text(font, str(item), Vec2(header_pos.x, item_y), rl.Color(255, 255, 255, alpha))


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
