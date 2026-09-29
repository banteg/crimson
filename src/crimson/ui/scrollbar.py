from __future__ import annotations

import msgspec

from grim.geom import Vec2

from .focus import UiFocus


class UiScrollbar(msgspec.Struct):
    """Native `ui_scrollbar_t`'s scroll state; the screens draw their own rows and thumbs."""

    item_count: int = 0
    visible_rows: int = 10
    scroll_offset: int = 0
    # Native's static scrollbars start with the first row selected.
    selected_index: int = 0
    focused: bool = False
    # The keys moved the cursor since the list took the focus (see `ui_scrollbar_update_keys`).
    keyed: bool = False

    @property
    def max_scroll(self) -> int:
        return max(0, self.item_count - self.visible_rows)

    def clamp(self) -> None:
        self.scroll_offset = max(0, min(self.max_scroll, self.scroll_offset))


def ui_scrollbar_update_keys(focus: UiFocus, bar: UiScrollbar, *, cursor: bool = False) -> None:
    """`ui_scrollbar_update`'s keyboard half: Up/Down scroll a row while focused; PgUp/PgDn page even when not.

    Native scrollbars never take focus from the mouse. With `cursor`, Up/Down move `selected_index` instead and the
    view follows it: the port's keyboard path to a row, since native only shows a row's details under the mouse.
    `keyed` tells the screen the keys have moved it since the list took the focus.
    """
    focused = focus.update(bar)
    bar.focused = focused
    bar.keyed = bar.keyed and focused
    if focused:
        step = int(focus.down) - int(focus.up)
        if cursor and step and bar.item_count > 0:
            bar.keyed = True
            bar.selected_index = max(0, min(bar.item_count - 1, bar.selected_index + step))
            if bar.selected_index < bar.scroll_offset:
                bar.scroll_offset = bar.selected_index
            elif bar.selected_index >= bar.scroll_offset + bar.visible_rows:
                bar.scroll_offset = bar.selected_index - bar.visible_rows + 1
        else:
            bar.scroll_offset += step
    if focus.page_up:
        bar.scroll_offset -= bar.visible_rows - 1
    if focus.page_down:
        bar.scroll_offset += bar.visible_rows - 1
    bar.clamp()
    if focused:
        # The pad's up/down walk the list until its end, then move the focus on.
        if cursor:
            focus.hold(up=bar.selected_index > 0, down=bar.selected_index < bar.item_count - 1)
        else:
            focus.hold(up=bar.scroll_offset > 0, down=bar.scroll_offset < bar.max_scroll)


def ui_scrollbar_draw_focus(focus: UiFocus, bar: UiScrollbar, pos: Vec2) -> None:
    """`ui_scrollbar_update`'s focus marker, 16px left of the list frame."""
    if bar.focused:
        focus.draw(pos.offset(dx=-16.0))


__all__ = ["UiScrollbar", "ui_scrollbar_draw_focus", "ui_scrollbar_update_keys"]
