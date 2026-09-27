from __future__ import annotations

import msgspec

from grim.geom import Vec2

UI_BASE_WIDTH = 640.0
UI_BASE_HEIGHT = 480.0


class DropdownLayoutBase(msgspec.Struct, frozen=True):
    pos: Vec2
    width: float
    header_h: float
    row_h: float
    rows_y0: float
    full_h: float


# Identity placeholders: the UI draws in backbuffer pixels. Their callers still
# thread `scale` through widget helpers that ignore it; remove both together.
def ui_scale(screen_w: float, screen_h: float) -> float:  # noqa: ARG001
    return 1.0


def ui_origin(screen_w: float, screen_h: float, scale: float) -> Vec2:  # noqa: ARG001
    return Vec2()


def menu_widescreen_y_shift(layout_w: float) -> float:
    # ui_menu_layout_init: pos_y += (screen_width / 640.0) * 150.0 - 150.0
    return (layout_w / UI_BASE_WIDTH) * 150.0 - 150.0
