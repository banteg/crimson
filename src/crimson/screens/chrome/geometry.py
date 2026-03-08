from __future__ import annotations

import math

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

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

MENU_DEMO_IDLE_START_MS = 23_000


class SinglePanelFrame(msgspec.Struct, frozen=True):
    scale: float
    panel_top_left: Vec2
    panel_width: float
    panel_height: float
    slide_x: float


class SplitPanelFrame(msgspec.Struct, frozen=True):
    scale: float
    panel_width: float
    left_top_left: Vec2
    right_top_left: Vec2
    left_slide_x: float
    right_slide_x: float
    left_panel_height: float
    right_panel_height: float


class SignFrame(msgspec.Struct, frozen=True):
    pos: Vec2
    width: float
    height: float
    origin: rl.Vector2
    rotation_deg: float


def label_alpha(counter_value: int) -> int:
    return 100 + (int(counter_value) * 155) // 1000


def menu_widescreen_y_shift(screen_w: float) -> float:
    return (float(screen_w) * 0.0015625 * 150.0) - 150.0


def menu_item_scale(screen_width: float, slot: int, *, small_scale: float = 0.9) -> tuple[float, float]:
    if float(screen_width) < 641.0:
        return float(small_scale), float(slot) * 11.0
    return 1.0, 0.0


def menu_slot_pos_x(slot: int) -> float:
    return MENU_LABEL_BASE_X - float(slot * 20)


def menu_slot_start_ms(slot: int) -> int:
    return (int(slot) + 2) * 100 + 300


def menu_slot_end_ms(slot: int) -> int:
    return (int(slot) + 2) * 100


def menu_max_timeline_ms(*, full_version: bool, mods_available: bool, other_games: bool) -> int:
    del full_version
    max_ms = 300
    slot_active = [mods_available, True, True, True, True, other_games]
    for slot, active in enumerate(slot_active):
        if active:
            max_ms = max(max_ms, menu_slot_start_ms(slot))
    return max_ms


def ui_element_anim(
    timeline_ms: int,
    *,
    index: int,
    start_ms: int,
    end_ms: int,
    width: float,
    direction_flag: int = 0,
) -> tuple[float, float]:
    if int(start_ms) <= int(end_ms) or float(width) <= 0.0:
        return 0.0, 0.0
    dir_sign = 1.0 if int(direction_flag) else -1.0
    t = int(timeline_ms)
    if t < int(end_ms):
        angle = 1.5707964
        offset_x = dir_sign * abs(float(width))
    elif t < int(start_ms):
        elapsed = t - int(end_ms)
        span = float(int(start_ms) - int(end_ms))
        p = float(elapsed) / span
        angle = 1.5707964 * (1.0 - p)
        offset_x = dir_sign * ((1.0 - p) * abs(float(width)))
    else:
        angle = 0.0
        offset_x = 0.0
    if int(index) == 0:
        angle = -abs(angle)
    return angle, offset_x


def sign_layout_scale(width: int) -> tuple[float, float]:
    if int(width) <= MENU_SCALE_SMALL_THRESHOLD:
        return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
    if MENU_SCALE_LARGE_MIN <= int(width) <= MENU_SCALE_LARGE_MAX:
        return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
    return 1.0, 0.0


def single_panel_frame(
    timeline_ms: int,
    *,
    screen_width: float,
    widescreen_y_shift: float,
    panel_pos: Vec2,
    panel_offset: Vec2,
    panel_height: float,
    panel_width: float = MENU_PANEL_WIDTH,
    index: int = 1,
    direction_flag: int = 0,
    small_scale: float = 0.9,
    slot: int = 0,
    start_ms: int = 300,
    end_ms: int = 0,
) -> SinglePanelFrame:
    scale, _local_y_shift = menu_item_scale(screen_width, slot, small_scale=small_scale)
    _angle_rad, slide_x = ui_element_anim(
        int(timeline_ms),
        index=index,
        start_ms=start_ms,
        end_ms=end_ms,
        width=float(panel_width) * scale,
        direction_flag=direction_flag,
    )
    panel_top_left = (
        Vec2(float(panel_pos.x) + float(slide_x), float(panel_pos.y) + float(widescreen_y_shift))
        + Vec2(float(panel_offset.x) * scale, float(panel_offset.y) * scale)
    )
    return SinglePanelFrame(
        scale=scale,
        panel_top_left=panel_top_left,
        panel_width=float(panel_width) * scale,
        panel_height=float(panel_height) * scale,
        slide_x=float(slide_x),
    )


def split_panel_frame(
    timeline_ms: int,
    *,
    left_panel_pos: Vec2,
    left_panel_height: float,
    right_panel_pos: Vec2,
    right_panel_height: float,
    screen_width: float,
    widescreen_y_shift: float,
    panel_offset: Vec2 = Vec2(MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y),
    panel_width: float = MENU_PANEL_WIDTH,
    small_scale: float = 1.0,
    left_index: int = 1,
    right_index: int = 2,
    start_ms: int = 300,
    end_ms: int = 0,
) -> SplitPanelFrame:
    scale, _local_y_shift = menu_item_scale(screen_width, 0, small_scale=small_scale)
    _angle_rad, left_slide_x = ui_element_anim(
        int(timeline_ms),
        index=left_index,
        start_ms=start_ms,
        end_ms=end_ms,
        width=float(panel_width) * scale,
        direction_flag=0,
    )
    _angle_rad, right_slide_x = ui_element_anim(
        int(timeline_ms),
        index=right_index,
        start_ms=start_ms,
        end_ms=end_ms,
        width=float(panel_width) * scale,
        direction_flag=1,
    )
    offset = Vec2(float(panel_offset.x) * scale, float(panel_offset.y) * scale)
    left_base = Vec2(float(left_panel_pos.x), float(left_panel_pos.y) + float(widescreen_y_shift)) + offset
    right_base = Vec2(float(right_panel_pos.x), float(right_panel_pos.y) + float(widescreen_y_shift)) + offset
    return SplitPanelFrame(
        scale=scale,
        panel_width=float(panel_width) * scale,
        left_top_left=left_base.offset(dx=float(left_slide_x)),
        right_top_left=right_base.offset(dx=float(right_slide_x)),
        left_slide_x=float(left_slide_x),
        right_slide_x=float(right_slide_x),
        left_panel_height=float(left_panel_height) * scale,
        right_panel_height=float(right_panel_height) * scale,
    )


def sign_frame(
    timeline_ms: int,
    *,
    screen_width: float,
    sign_locked: bool,
    animated: bool,
) -> SignFrame:
    scale, shift_x = sign_layout_scale(int(screen_width))
    pos = Vec2(
        float(screen_width) + MENU_SIGN_POS_X_PAD,
        MENU_SIGN_POS_Y if float(screen_width) > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
    )
    sign_w = MENU_SIGN_WIDTH * scale
    sign_h = MENU_SIGN_HEIGHT * scale
    offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
    offset_y = MENU_SIGN_OFFSET_Y * scale
    rotation_deg = 0.0
    if animated and not bool(sign_locked):
        angle_rad, _slide_x = ui_element_anim(
            int(timeline_ms),
            index=0,
            start_ms=300,
            end_ms=0,
            width=sign_w,
            direction_flag=0,
        )
        rotation_deg = math.degrees(angle_rad)
    return SignFrame(
        pos=pos,
        width=sign_w,
        height=sign_h,
        origin=rl.Vector2(-offset_x, -offset_y),
        rotation_deg=rotation_deg,
    )
