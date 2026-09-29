from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from .hit_test import mouse_inside_rect_with_padding


class UiListWidget(msgspec.Struct):
    """Native `ui_list_widget_t`; callers assign `items` every frame, as native does."""

    enabled: bool = True
    open: bool = False
    selected_index: int = 0
    items: tuple[str, ...] = ()
    hovered: bool = False
    active_index: int = 0


def _list_widget_size(resources: RuntimeResources, widget: UiListWidget) -> tuple[float, float]:
    """The widest item plus 48 by 16, or `item_count * 16 + 24` tall while open."""
    width = max((measure_small_text_width(resources.small_font, item) for item in widget.items), default=0.0) + 48.0
    height = float(len(widget.items) * 16 + 24) if widget.open else 16.0
    return width, height


def ui_list_widget_update(resources: RuntimeResources, widget: UiListWidget, pos: Vec2, *, mouse: Vec2) -> int:
    """`ui_list_widget_update`'s input half.

    Returns -2 when idle, -1 when the (enabled) header is hit, and `active_index` while open; the caller toggles
    `open` and takes a row on `>= -1` plus a press. An open list closes once the mouse leaves it. Native's keyboard
    focus (`ui_focus_update`, the arrow keys and the focus marker) is not ported, so the list is never focused.
    """
    if not widget.enabled:
        widget.open = False
    width, height = _list_widget_size(resources, widget)
    # `ui_mouse_inside_rect`: strictly inside the whole (open) list.
    widget.hovered = widget.open and pos.x < mouse.x < pos.x + width and pos.y < mouse.y < pos.y + height

    result = -1 if widget.enabled and mouse_inside_rect_with_padding(mouse, pos=pos, width=width, height=14.0) else -2
    if not widget.open:
        return result
    for index in range(len(widget.items)):
        row_pos = pos.offset(dy=float(index * 16 + 16))
        if mouse_inside_rect_with_padding(mouse, pos=row_pos, width=width, height=14.0):
            widget.active_index = index
    if not widget.hovered:
        widget.open = False
    return widget.active_index


def ui_list_widget_draw(resources: RuntimeResources, widget: UiListWidget, pos: Vec2, *, mouse: Vec2) -> None:
    """`ui_list_widget_update`'s draw half: the bordered box, the arrow, the selected item and, while open, the rows."""
    width, height = _list_widget_size(resources, widget)
    rl.draw_rectangle_rec(rl.Rectangle(pos.x, pos.y, width, height), rl.WHITE)
    rl.draw_rectangle_rec(rl.Rectangle(pos.x + 1.0, pos.y + 1.0, width - 2.0, height - 2.0), rl.BLACK)

    if widget.open or widget.hovered:
        rl.draw_rectangle_rec(rl.Rectangle(pos.x, pos.y + 15.0, width, 1.0), grim_color(1.0, 1.0, 1.0, 0.5))
        arrow = resources.texture(TextureId.UI_DROP_ON)
    else:
        arrow = resources.texture(TextureId.UI_DROP_OFF)
    rl.draw_texture_pro(
        arrow,
        rl.Rectangle(0.0, 0.0, float(arrow.width), float(arrow.height)),
        rl.Rectangle(pos.x + width - 16.0 - 1.0, pos.y, 16.0, 16.0),
        rl.Vector2(0.0, 0.0),
        0.0,
        rl.WHITE,
    )

    font = resources.small_font
    header_hit = widget.enabled and mouse_inside_rect_with_padding(mouse, pos=pos, width=width, height=14.0)
    header_color = grim_color(1.0, 1.0, 1.0, 0.95 if header_hit else 0.75)
    draw_small_text(font, widget.items[widget.selected_index], pos.offset(dx=4.0, dy=1.0), header_color)
    if not widget.open:
        return

    for index, item in enumerate(widget.items):
        row_pos = pos.offset(dy=float(index * 16 + 16))
        row_hit = mouse_inside_rect_with_padding(mouse, pos=row_pos, width=width, height=14.0)
        row_color = grim_color(1.0, 1.0, 1.0, 0.95 if row_hit else 0.6)
        draw_small_text(font, item, pos.offset(dx=4.0, dy=float(index * 16) + 17.0), row_color)
