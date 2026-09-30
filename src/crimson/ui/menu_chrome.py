from __future__ import annotations

import math

from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.raylib_api import rl

from .animation import ui_element_anim, ui_element_offset_render
from .menu_layout import (
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    MenuEntry,
    label_alpha,
    menu_entry_enabled,
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


def draw_menu_entry(resources: RuntimeResources, entry: MenuEntry, *, timeline_ms: int, shadows: bool) -> None:
    """`ui_element_render` for a menu item: the quad, its label row at the hover's alpha, then, once the item is in,
    the label again additively at that alpha. Transform items swing in about their position, offset ones slide."""

    item = resources.texture(TextureId.UI_MENU_ITEM)
    label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
    item_scale = entry.scale
    local_y_shift = entry.rise
    angle_rad, slide_x = ui_element_anim(timeline_ms, index=entry.element, width=float(item.width) * item_scale)
    if ui_element_offset_render(entry.element):
        pos = entry.pos.offset(dx=slide_x)
        rotation_deg = 0.0
    else:
        pos = entry.pos
        rotation_deg = math.degrees(angle_rad)
    item_src = rl.Rectangle(0.0, 0.0, float(item.width), float(item.height))
    dst = rl.Rectangle(pos.x, pos.y, float(item.width) * item_scale, float(item.height) * item_scale)
    origin = rl.Vector2(-MENU_ITEM_OFFSET_X * item_scale, -(MENU_ITEM_OFFSET_Y * item_scale - local_y_shift))
    if shadows:
        draw_ui_quad_shadow(
            texture=item,
            src=item_src,
            dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
            origin=origin,
            rotation_deg=rotation_deg,
        )
    rl.draw_texture_pro(item, item_src, dst, origin, rotation_deg, rl.WHITE)
    label_src = rl.Rectangle(0.0, float(entry.row) * MENU_LABEL_ROW_HEIGHT, MENU_LABEL_WIDTH, MENU_LABEL_ROW_HEIGHT)
    label_dst = rl.Rectangle(pos.x, pos.y, MENU_LABEL_WIDTH * item_scale, MENU_LABEL_HEIGHT * item_scale)
    label_origin = rl.Vector2(-MENU_LABEL_OFFSET_X * item_scale, -(MENU_LABEL_OFFSET_Y * item_scale - local_y_shift))
    label_tint = rl.Color(255, 255, 255, label_alpha(entry.hover_amount))
    rl.draw_texture_pro(label_tex, label_src, label_dst, label_origin, rotation_deg, label_tint)
    if menu_entry_enabled(entry, timeline_ms):
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        rl.draw_texture_pro(label_tex, label_src, label_dst, label_origin, rotation_deg, label_tint)
        rl.end_blend_mode()


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
