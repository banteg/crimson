from __future__ import annotations

import msgspec

from grim.geom import Rect, Vec2

from .animation import ui_element_timeline_window
from .focus import UiFocus
from .layout import menu_widescreen_y_shift

MENU_LABEL_WIDTH = 122.0
MENU_LABEL_HEIGHT = 28.0
MENU_LABEL_ROW_HEIGHT = 32.0
MENU_LABEL_ROW_PLAY_GAME = 1
MENU_LABEL_ROW_OPTIONS = 2
MENU_LABEL_ROW_STATISTICS = 3
MENU_LABEL_ROW_OTHER_GAMES = 5
MENU_LABEL_ROW_QUIT = 6
MENU_LABEL_ROW_BACK = 7
MENU_LABEL_BASE_X = -60.0
MENU_LABEL_BASE_Y = 210.0
MENU_LABEL_OFFSET_X = 271.0
MENU_LABEL_OFFSET_Y = -37.0
MENU_LABEL_STEP = 60.0
MENU_ITEM_OFFSET_X = -71.0
MENU_ITEM_OFFSET_Y = -59.0
MENU_PANEL_WIDTH = 510.0
MENU_SCALE_SMALL_THRESHOLD = 640
MENU_SCALE_LARGE_MIN = 801
MENU_SCALE_LARGE_MAX = 1024
MENU_SCALE_SMALL = 0.8
MENU_SCALE_LARGE = 1.2
MENU_SCALE_SHIFT = 10.0

MENU_SIGN_WIDTH = 571.44
MENU_SIGN_HEIGHT = 141.36
MENU_SIGN_OFFSET_X = -576.44
MENU_SIGN_OFFSET_Y = -61.0
MENU_SIGN_POS_Y = 70.0
MENU_SIGN_POS_Y_SMALL = 60.0
MENU_SIGN_POS_X_PAD = 4.0


def ui_element_pos(index: int, screen_width: float) -> Vec2:
    """`ui_menu_layout_init`: where `ui_element_table[index]` sits. Every element moves down with the window width,
    except the controls' right panel (slot 40), which is placed after that."""
    width = int(screen_width)
    shift_y = menu_widescreen_y_shift(float(width))
    match index:
        case 9:
            return Vec2(-85.0 if width <= 640 else -35.0, 185.0 + shift_y)
        case 11 | 31:
            return Vec2(-45.0, 210.0 + shift_y)
        case 12:
            return Vec2(-55.0, 462.0 + shift_y)
        case 14:
            return Vec2(-183.0 if width <= 640 else -165.0, 200.0 + shift_y)
        case 18:
            return Vec2(-155.0, 420.0 + shift_y)
        case 27 | 30 | 35:
            return Vec2(-45.0, 110.0 + shift_y)
        case 32:
            return Vec2(-55.0, 430.0 + shift_y)
        case 33:
            x = float(width - 350)
            if width > 800:
                x -= 65.0
            elif width > 640:
                x -= 30.0
            else:
                x += 10.0
            return Vec2(x, 200.0 + shift_y)
        case 37 | 39:
            return Vec2(-5.0, 185.0 + shift_y)
        case 40:
            return Vec2(float(width - 270), 186.0) if width <= 640 else Vec2(float(width - 350), 200.0)
        case _:
            raise ValueError(index)


class MenuEntry(msgspec.Struct):
    """A menu item element (a `ui_element_t` with a label row and an `on_activate`): its `ui_element_table` index,
    where `ui_menu_layout_init` put it and how far it shrank and rose, and its hover ramp."""

    element: int
    row: int
    pos: Vec2
    scale: float = 1.0
    rise: float = 0.0
    hover_amount: int = 0
    hovered: bool = False
    focused: bool = False


def menu_item_bounds(pos: Vec2, item_size: Vec2, item_scale: float, local_y_shift: float) -> Rect:
    """`ui_element_layout_calc`: the clickable inset of a menu item quad at `pos`."""

    offset_min = Vec2(MENU_ITEM_OFFSET_X * item_scale, MENU_ITEM_OFFSET_Y * item_scale - local_y_shift)
    offset_max = Vec2(
        (MENU_ITEM_OFFSET_X + item_size.x) * item_scale,
        (MENU_ITEM_OFFSET_Y + item_size.y) * item_scale - local_y_shift,
    )
    size = offset_max - offset_min
    top_left = pos + Vec2(offset_min.x + size.x * 0.54, offset_min.y + size.y * 0.28)
    bottom_right = pos + Vec2(offset_max.x - size.x * 0.05, offset_max.y - size.y * 0.10)
    return Rect.from_pos_size(top_left, bottom_right - top_left)


def menu_entry_update(
    entry: MenuEntry, *, item_size: Vec2, mouse: Vec2, dt_ms: int, focus: UiFocus, live: bool,
) -> None:
    """`ui_element_update`, then `ui_element_render`'s focus, for a menu item.

    The item is hovered while the mouse is over its bounds, which stay where the layout put them while it swings or
    slides in, and its hover ramps up 6 per ms and down 2 per ms; a focused item's hover is pinned to the focus timer.
    The update runs on while the timeline runs out (`live` off), when the screen's widgets stop registering for focus.
    """
    entry.hovered = menu_item_bounds(entry.pos, item_size, entry.scale, entry.rise).contains(mouse)
    if entry.hovered:
        entry.hover_amount += dt_ms * 6
    else:
        entry.hover_amount -= dt_ms * 2
    entry.hover_amount = max(0, min(1000, entry.hover_amount))
    if live:
        entry.focused = focus.update(entry)
    if entry.focused and focus.timer_ms > 0:
        entry.hover_amount = focus.timer_ms


def menu_entry_enabled(entry: MenuEntry, timeline_ms: int) -> bool:
    """`ui_element_update` enables an item once the timeline reaches its `timeline_end_ms`."""
    return timeline_ms >= ui_element_timeline_window(entry.element)[1]


def menu_entry_activated(entry: MenuEntry, *, timeline_ms: int, focus: UiFocus, click: bool) -> bool:
    """A click on the hovered item (`ui_element_update`: its `time_since_ready` gate starts past 255 and only
    grows, so a sliding item takes clicks too), or Enter while it holds the focus once it is in
    (`ui_element_render`)."""
    return (entry.hovered and click) or (entry.focused and focus.enter and menu_entry_enabled(entry, timeline_ms))


def label_alpha(hover_amount: int) -> int:
    # ui_element_render: alpha = 100 + floor(hover_amount * 155 / 1000)
    return 100 + (hover_amount * 155) // 1000


def menu_slot_pos_x(slot: int) -> float:
    # ui_menu_layout_init: subtract 20, 40, ... from later menu items
    return MENU_LABEL_BASE_X - float(slot * 20)


def main_menu_item_scale(width: int, slot: int) -> tuple[float, float]:
    """Return (scale, rise) for main menu item `slot` (`ui_element_table[slot + 2]`)."""
    # ui_menu_layout_init: items 1..7 shrink to 0.9 and rise (i - 2) * 11 at <= 640.
    if width <= MENU_SCALE_SMALL_THRESHOLD:
        return 0.9, float(slot) * 11.0
    return 1.0, 0.0


def pause_menu_item_scale(width: int, slot: int) -> tuple[float, float]:
    """Return (scale, rise) for pause menu item `slot` (`ui_element_table[slot + 23]`)."""
    # ui_menu_layout_init: items 22..25 shrink to 0.8 and rise (i - 23) * 11 at <= 640,
    # or shrink to 0.9 and rise (i - 23) * 5 at <= 800.
    if width <= MENU_SCALE_SMALL_THRESHOLD:
        return 0.8, float(slot) * 11.0
    if width < MENU_SCALE_LARGE_MIN:
        return 0.9, float(slot) * 5.0
    return 1.0, 0.0


def back_button_scale(width: int) -> tuple[float, float]:
    """Return (scale, rise) for the panel back buttons (`ui_menu_layout_a/b/c`)."""
    # ui_menu_layout_init: shrink to 0.8 and rise 11 at <= 640, or 0.9 and rise 3 at <= 800.
    if width <= MENU_SCALE_SMALL_THRESHOLD:
        return 0.8, 11.0
    if width < MENU_SCALE_LARGE_MIN:
        return 0.9, 3.0
    return 1.0, 0.0


def sign_layout_scale(width: int) -> tuple[float, float]:
    if width <= MENU_SCALE_SMALL_THRESHOLD:
        return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
    if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
        return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
    return 1.0, 0.0
