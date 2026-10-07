from __future__ import annotations

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.color import grim_color
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2

from .focus import UiFocus
from .hit_test import mouse_inside_rect_with_padding


class UiListWidget(msgspec.Struct):
    """Native `ui_list_widget_t`; callers assign `items` every frame, as native does."""

    enabled: bool = True
    open: bool = False
    selected_index: int = 0
    items: tuple[str, ...] = ()
    hovered: bool = False
    active_index: int = 0
    focused: bool = False


def ui_list_widget_width(resources: RuntimeResources, widget: UiListWidget) -> float:
    """The widest item plus 48."""
    return max((measure_small_text_width(resources.small_font, item) for item in widget.items), default=0.0) + 48.0


def _list_widget_size(resources: RuntimeResources, widget: UiListWidget) -> tuple[float, float]:
    """`ui_list_widget_width` by 16, or `item_count * 16 + 24` tall while open."""
    height = float(len(widget.items) * 16 + 24) if widget.open else 16.0
    return ui_list_widget_width(resources, widget), height


def ui_list_widget_update(
    resources: RuntimeResources,
    widget: UiListWidget,
    pos: Vec2,
    *,
    focus: UiFocus,
    mouse: Vec2,
    click: bool,
    preserve_bugs: bool,
) -> int:
    """`ui_list_widget_update`'s input half.

    Returns -2 when idle, -1 when the (enabled) header is hit, and `active_index` while open; the caller toggles
    `open` and takes a row on `>= -1` plus a press (a click or Enter). While focused, Up/Down open the list or move
    `active_index`. An open list closes once it is neither hovered nor focused.

    Native only opens a list from the keyboard with the arrow keys, and its Enter reaches the list only while the
    mouse is on the header; the port also reports the header hit on Enter while focused, so Enter opens it.

    Hovering an open list focuses it, so native keeps it open after the mouse leaves, and the next click anywhere
    takes the row last hovered. The port reports that stray click as a header hit instead: the caller closes the
    list without taking a row. `preserve_bugs` keeps the native pick.
    """
    focused = focus.update(widget)
    widget.focused = focused
    if not widget.enabled:
        widget.open = False
    width, height = _list_widget_size(resources, widget)
    # `ui_mouse_inside_rect`: strictly inside the whole (open) list.
    widget.hovered = widget.open and pos.x < mouse.x < pos.x + width and pos.y < mouse.y < pos.y + height
    if widget.hovered:
        focus.set(widget)

    if focused and widget.enabled:
        if focus.up:
            if widget.open:
                widget.active_index = max(0, widget.active_index - 1)
            else:
                widget.open = True
        if focus.down:
            if widget.open:
                widget.active_index = min(len(widget.items) - 1, widget.active_index + 1)
            else:
                widget.open = True

    header_hit = widget.enabled and mouse_inside_rect_with_padding(mouse, pos=pos, width=width, height=14.0)
    result = -1 if header_hit or (focused and focus.enter and widget.enabled) else -2
    if focused:
        # A list that stays open (Enter makes the caller toggle it) walks its rows with the pad's up/down.
        stays_open = widget.open != (focus.enter and widget.enabled)
        focus.hold(up=stays_open, down=stays_open)
    if not widget.open:
        return result
    for index in range(len(widget.items)):
        row_pos = pos.offset(dy=float(index * 16 + 16))
        if mouse_inside_rect_with_padding(mouse, pos=row_pos, width=width, height=14.0):
            widget.active_index = index
    if not widget.hovered and not focused:
        widget.open = False
    if click and not widget.hovered and not header_hit and not preserve_bugs:
        return -1
    return widget.active_index


def ui_list_widget_draw(
    resources: RuntimeResources, widget: UiListWidget, pos: Vec2, *, focus: UiFocus, mouse: Vec2,
) -> None:
    """`ui_list_widget_update`'s draw half: the focus marker, the bordered box, the arrow, the selected item and,
    while open, the rows (the focused list lights its active row)."""
    if widget.focused:
        focus.draw(pos.offset(dx=-16.0))
    width, height = _list_widget_size(resources, widget)
    rl.draw_rectangle_rec(rl_rectangle(pos.x, pos.y, width, height), rl.WHITE)
    rl.draw_rectangle_rec(rl_rectangle(pos.x + 1.0, pos.y + 1.0, width - 2.0, height - 2.0), rl.BLACK)

    if widget.open or widget.hovered:
        rl.draw_rectangle_rec(rl_rectangle(pos.x, pos.y + 15.0, width, 1.0), grim_color(1.0, 1.0, 1.0, 0.5))
        arrow = resources.texture(TextureId.UI_DROP_ON)
    else:
        arrow = resources.texture(TextureId.UI_DROP_OFF)
    rl.draw_texture_pro(
        arrow,
        rl_rectangle(0.0, 0.0, float(arrow.width), float(arrow.height)),
        rl_rectangle(pos.x + width - 16.0 - 1.0, pos.y, 16.0, 16.0),
        rl_vector2(0.0, 0.0),
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
        row_alpha = 0.95 if row_hit else 0.6
        if widget.focused and widget.active_index == index:
            row_alpha = 0.96
        row_color = grim_color(1.0, 1.0, 1.0, row_alpha)
        draw_small_text(font, item, pos.offset(dx=4.0, dy=float(index * 16) + 17.0), row_color)
