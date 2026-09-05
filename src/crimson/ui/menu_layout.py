from __future__ import annotations

import msgspec

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


def sign_layout_scale(width: int) -> tuple[float, float]:
    if width <= MENU_SCALE_SMALL_THRESHOLD:
        return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
    if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
        return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
    return 1.0, 0.0
