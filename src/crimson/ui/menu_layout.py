from __future__ import annotations

import msgspec

from grim.geom import Rect, Vec2

MENU_LABEL_WIDTH = 122.0
MENU_LABEL_HEIGHT = 28.0
MENU_LABEL_ROW_HEIGHT = 32.0
MENU_LABEL_ROW_PLAY_GAME = 1
MENU_LABEL_ROW_OPTIONS = 2
MENU_LABEL_ROW_STATISTICS = 3
MENU_LABEL_ROW_MODS = 4
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
MENU_PANEL_HEIGHT = 254.0
# Measured from ui_render_trace at 1024x768 (stable timeline):
# panel top-left is (pos_x + 21, pos_y - 81) and size is 510x254, plus a shadow pass at +7,+7.
MENU_PANEL_OFFSET_X = 21.0
MENU_PANEL_OFFSET_Y = -81.0
MENU_PANEL_BASE_X = -45.0
MENU_PANEL_BASE_Y = 210.0
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


class MenuEntry(msgspec.Struct):
    slot: int
    row: int
    y: float
    hover_amount: int = 0
    ready_timer_ms: int = 0x100


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


def update_menu_item_timers(entries: list[MenuEntry], hovered_index: int | None, dt_ms: int) -> None:
    """`ui_element_update`: the ready glow ramp and the hover fade of each item."""

    for idx, entry in enumerate(entries):
        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)
        if hovered_index is not None and idx == hovered_index:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))


def label_alpha(counter_value: int) -> int:
    # ui_element_render: alpha = 100 + floor(counter_value * 155 / 1000)
    return 100 + (counter_value * 155) // 1000


def menu_slot_pos_x(slot: int) -> float:
    # ui_menu_layout_init: subtract 20, 40, ... from later menu items
    return MENU_LABEL_BASE_X - float(slot * 20)


def menu_slot_start_ms(slot: int) -> int:
    # ui_menu_layout_init: start_time_ms is the fully-visible time.
    return (slot + 2) * 100 + 300


def menu_slot_end_ms(slot: int) -> int:
    # ui_menu_layout_init: end_time_ms is the fully-hidden time.
    return (slot + 2) * 100


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
