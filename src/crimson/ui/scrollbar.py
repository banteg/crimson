from __future__ import annotations

import msgspec

from grim.color import grim_color
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from .focus import UiFocus


class UiScrollbar(msgspec.Struct):
    """Native `ui_scrollbar_t`: a 250px list box of `visible_rows` 16px rows with a scrollbar once the items overflow.

    Callers assign `items` every frame, as native does; an item's tabs split it into columns `column_offsets[i] * i`
    to the right, and a leading `\\g` draws it green.
    """

    items: list[str] = msgspec.field(default_factory=list)
    column_offsets: tuple[int, ...] = (0, 0, 0, 0, 0, 0, 0, 0)
    visible_rows: int = 10
    scroll_offset: float = 0.0
    hovered_index: int = -1
    # Native's static scrollbars start with the first row selected.
    selected_index: int = 0
    focused: bool = False
    # The keys moved the cursor since the list took the focus (see `ui_scrollbar_update`'s `cursor`).
    keyed: bool = False
    # Native `ui_scrollbar_drag_active` / `ui_scrollbar_drag_offset`, globals shared by every scrollbar.
    drag_active: bool = False
    drag_offset: float = 0.0

    @property
    def item_count(self) -> int:
        return len(self.items)

    @property
    def max_scroll(self) -> int:
        return max(0, self.item_count - self.visible_rows)


def _mouse_inside_rect(mouse: Vec2, pos: Vec2, h: int, w: int) -> bool:
    """`ui_mouse_inside_rect`: strictly inside."""
    return pos.x < mouse.x < pos.x + float(w) and pos.y < mouse.y < pos.y + float(h)


def _thumb(bar: UiScrollbar, pos: Vec2) -> tuple[Vec2, float]:
    """The thumb's top-left and height: it moves in whole rows over the track inside the frame."""
    height = float(bar.visible_rows * 16 + 4)
    interior_height = height - 2.0
    thumb_height = float(bar.visible_rows) / float(bar.item_count) * interior_height
    if thumb_height > interior_height:
        thumb_height = height - 3.0
    max_scroll = bar.item_count - bar.visible_rows
    first_item = int(bar.scroll_offset)
    return Vec2(pos.x + 241.0, pos.y + (height - 3.0 - thumb_height) / float(max_scroll) * float(first_item) + 1.0), thumb_height


def ui_scrollbar_row_under_mouse(bar: UiScrollbar, pos: Vec2, mouse: Vec2) -> int:
    """The item under the mouse, or -1: each row is hot 2px left of the frame, 240px wide and 17px tall, so a row
    overlaps the next by a pixel and the lower one wins."""
    pos = Vec2(float(int(pos.x)), float(int(pos.y)))
    hovered_index = -1
    for row in range(min(bar.visible_rows, bar.item_count)):
        if _mouse_inside_rect(mouse, Vec2(pos.x - 2.0, pos.y + float(row * 16)), 17, 240):
            hovered_index = int(bar.scroll_offset) + row
    return hovered_index


def ui_scrollbar_update(
    focus: UiFocus,
    bar: UiScrollbar,
    pos: Vec2,
    *,
    mouse: Vec2,
    click: bool,
    down: bool,
    wheel: float,
    cursor: bool = False,
) -> None:
    """`ui_scrollbar_update`'s input half: the wheel, Up/Down while focused, PgUp/PgDn, the thumb drag, then the
    row under the mouse (`hovered_index`), which a click selects.

    Native scrollbars never take focus from the mouse. The track, 10px from the frame's right edge, arms the drag
    while hovered; a press on the thumb keeps its grab point, a press elsewhere on the track grabs the thumb's top,
    and the drag follows the mouse anywhere while the button stays down.

    With `cursor`, Up/Down move `selected_index` instead and the view follows it: the port's keyboard path to a row,
    since native only shows a row's details under the mouse. `keyed` tells the screen the keys have moved it since
    the list took the focus.
    """
    pos = Vec2(float(int(pos.x)), float(int(pos.y)))
    bar.hovered_index = -1
    focused = focus.update(bar)
    bar.focused = focused
    bar.keyed = bar.keyed and focused
    height = float(bar.visible_rows * 16 + 4)

    if wheel > 0.0:
        bar.scroll_offset -= 1.0
    if wheel < 0.0:
        bar.scroll_offset += 1.0

    if focused:
        step = int(focus.down) - int(focus.up)
        if cursor and step and bar.item_count > 0:
            bar.keyed = True
            bar.selected_index = max(0, min(bar.item_count - 1, bar.selected_index + step))
            if bar.selected_index < bar.scroll_offset:
                bar.scroll_offset = float(bar.selected_index)
            elif bar.selected_index >= bar.scroll_offset + bar.visible_rows:
                bar.scroll_offset = float(bar.selected_index - bar.visible_rows + 1)
        else:
            bar.scroll_offset += float(step)
    if focus.page_up:
        bar.scroll_offset -= float(bar.visible_rows - 1)
    if focus.page_down:
        bar.scroll_offset += float(bar.visible_rows - 1)

    max_scroll = bar.item_count - bar.visible_rows
    if float(max_scroll) < bar.scroll_offset:
        bar.scroll_offset = float(max_scroll)
    if bar.scroll_offset < 0.0:
        bar.scroll_offset = 0.0
    if focused:
        # The pad's up/down walk the list until its end, then move the focus on.
        if cursor:
            focus.hold(up=bar.selected_index > 0, down=bar.selected_index < bar.item_count - 1)
        else:
            focus.hold(up=bar.scroll_offset > 0.0, down=bar.scroll_offset < bar.max_scroll)

    if bar.item_count > bar.visible_rows:
        thumb_pos, thumb_height = _thumb(bar, pos)
        if _mouse_inside_rect(mouse, pos.offset(dx=240.0), int(height), 10):
            bar.drag_active = True
            if click:
                if _mouse_inside_rect(mouse, thumb_pos, int(thumb_height), 8):
                    bar.drag_offset = mouse.y - pos.y - bar.scroll_offset / float(bar.item_count) * height
                else:
                    bar.drag_offset = 0.0
        elif not down:
            bar.drag_active = False

        if bar.drag_active and down:
            bar.scroll_offset = (mouse.y - pos.y - bar.drag_offset) / height * float(bar.item_count)
            if bar.scroll_offset > float(bar.item_count - bar.visible_rows):
                bar.scroll_offset = float(bar.item_count - bar.visible_rows)
            if bar.scroll_offset < 0.0:
                bar.scroll_offset = 0.0

    bar.hovered_index = ui_scrollbar_row_under_mouse(bar, pos, mouse)
    if click and bar.hovered_index != -1:
        bar.selected_index = bar.hovered_index


def ui_scrollbar_draw(font: SmallFontData, focus: UiFocus, bar: UiScrollbar, pos: Vec2, *, mouse: Vec2) -> None:
    """`ui_scrollbar_update`'s draw half: the focus marker 16px left, the white framed black box, and once the items
    overflow, the divider and the thumb (brighter while the mouse is on the track); then the rows, the hovered one
    bright, the selected one at 0.9 and the rest at 0.7."""
    pos = Vec2(float(int(pos.x)), float(int(pos.y)))
    if bar.focused:
        focus.draw(pos.offset(dx=-16.0))
    height = float(bar.visible_rows * 16 + 4)
    rl.draw_rectangle_rec(rl.Rectangle(pos.x, pos.y, 250.0, height), grim_color(1.0, 1.0, 1.0, 1.0))
    rl.draw_rectangle_rec(rl.Rectangle(pos.x + 1.0, pos.y + 1.0, 248.0, height - 2.0), grim_color(0.0, 0.0, 0.0, 1.0))
    if bar.item_count > bar.visible_rows:
        rl.draw_rectangle_rec(rl.Rectangle(pos.x + 240.0, pos.y, 1.0, height), grim_color(1.0, 1.0, 1.0, 0.8))
        thumb_pos, thumb_height = _thumb(bar, pos)
        rl.draw_rectangle_rec(
            rl.Rectangle(thumb_pos.x, thumb_pos.y, 8.0, thumb_height + 1.0), grim_color(1.0, 1.0, 1.0, 0.8),
        )
        if _mouse_inside_rect(mouse, pos.offset(dx=240.0), int(height), 10):
            fill = grim_color(0.2, 0.4, 0.8, 1.0)
        else:
            fill = grim_color(0.1, 0.2, 0.4, 1.0)
        rl.draw_rectangle_rec(rl.Rectangle(thumb_pos.x + 1.0, thumb_pos.y + 1.0, 6.0, thumb_height - 1.0), fill)

    first_item = int(bar.scroll_offset)
    hovered_index = ui_scrollbar_row_under_mouse(bar, pos, mouse)
    for row in range(min(bar.visible_rows, bar.item_count)):
        item_index = first_item + row
        if item_index == hovered_index:
            alpha = 1.0
        elif item_index == bar.selected_index:
            alpha = 0.9
        else:
            alpha = 0.7
        text = bar.items[item_index]
        if text.startswith("\\g"):
            color = grim_color(0.7, 1.0, 0.7, alpha)
            text = text[2:]
        else:
            color = grim_color(1.0, 1.0, 1.0, alpha)
        for column, cell in enumerate(text.split("\t")):
            x_offset = bar.column_offsets[column] * column
            draw_small_text(font, cell, Vec2(pos.x - 2.0 + float(x_offset) + 8.0, pos.y + float(row * 16) + 2.0), color)


__all__ = ["UiScrollbar", "ui_scrollbar_draw", "ui_scrollbar_row_under_mouse", "ui_scrollbar_update"]
