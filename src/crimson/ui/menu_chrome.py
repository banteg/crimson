from __future__ import annotations

import math

from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl

from .animation import ui_element_anim
from .menu_layout import (
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    sign_layout_scale,
)
from .shadow import UI_SHADOW_OFFSET, draw_ui_quad_shadow


def draw_ui_quad(
    *,
    texture: rl.Texture,
    src: rl.Rectangle,
    dst: rl.Rectangle,
    origin: rl.Vector2,
    rotation_deg: float,
    tint: rl.Color,
) -> None:
    rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)


def draw_menu_sign(
    resources: RuntimeResources, *, width: int, shadows: bool, locked: bool = True, timeline_ms: int = 0,
) -> None:
    screen_w = float(width)
    scale, shift_x = sign_layout_scale(int(screen_w))
    sign_pos = Vec2(
        screen_w + MENU_SIGN_POS_X_PAD,
        MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
    )
    sign_w = MENU_SIGN_WIDTH * scale
    sign_h = MENU_SIGN_HEIGHT * scale
    offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
    offset_y = MENU_SIGN_OFFSET_Y * scale
    rotation_deg = 0.0
    if not locked:
        angle_rad, slide_x = ui_element_anim(
            timeline_ms,
            index=0,
            start_ms=300,
            end_ms=0,
            width=sign_w,
        )
        _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
        rotation_deg = math.degrees(angle_rad)
    sign = resources.texture(TextureId.UI_SIGN_CRIMSON)
    shadows_enabled = shadows
    if shadows_enabled:
        draw_ui_quad_shadow(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
        )
    draw_ui_quad(
        texture=sign,
        src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
        dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
        origin=rl.Vector2(-offset_x, -offset_y),
        rotation_deg=rotation_deg,
        tint=rl.WHITE,
    )
