from __future__ import annotations


UI_BASE_WIDTH = 640.0
UI_BASE_HEIGHT = 480.0


def ui_scale(screen_w: float, screen_h: float) -> float:
    # Classic UI-space: draw in backbuffer pixels.
    return 1.0


def ui_origin(screen_w: float, screen_h: float, scale: float) -> tuple[float, float]:
    return 0.0, 0.0


def menu_widescreen_y_shift(layout_w: float) -> float:
    # ui_menu_layout_init: pos_y += (screen_width / 640.0) * 150.0 - 150.0
    return (layout_w / UI_BASE_WIDTH) * 150.0 - 150.0

