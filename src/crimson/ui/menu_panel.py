from __future__ import annotations

import pyray as rl

from .shadow import UI_SHADOW_OFFSET, draw_ui_quad_shadow


# Classic menu panel is rendered from the *inset* inner region of ui_menuPanel:
#   - X inset: 1px on each side (uv 1/512 .. 511/512) => 510px wide
#   - Y inset: 1px on each side (uv 1/256 .. 255/256) => 254px tall
#
# When a panel is taller than the base height, the original stretches it using a
# 3-slice: [top][mid][bottom]. The source slice boundaries are at y=130 and y=150
# in the texture (see grim UVs in ui_render_trace).
MENU_PANEL_INSET = 1.0
MENU_PANEL_SRC_SLICE_Y1 = 130.0
MENU_PANEL_SRC_SLICE_Y2 = 150.0

# Destination slice heights observed in the original at scale=1.0 (1024x768).
MENU_PANEL_DST_TOP_H = 138.0
MENU_PANEL_DST_BOTTOM_H = 116.0


def draw_classic_menu_panel(
    texture: rl.Texture,
    *,
    dst: rl.Rectangle,
    tint: rl.Color = rl.WHITE,
    shadow: bool = False,
    flip_x: bool = False,
) -> None:
    """
    Draw a classic menu panel (ui_menuPanel) with the same slicing behavior as the original.

    - Uses inset source rect (1px border skipped) to match the vertex/UV inset.
    - Uses 3-slice only when dst is taller than (top + bottom); otherwise draws a single quad.
    """

    tex_w = float(texture.width)
    tex_h = float(texture.height)
    if tex_w <= 0.0 or tex_h <= 0.0:
        return

    inset = MENU_PANEL_INSET
    src_x = inset
    src_y = inset
    src_w = max(0.0, tex_w - inset * 2.0)
    src_h = max(0.0, tex_h - inset * 2.0)

    # Scale slice heights with the panel width (menu panel uses the same scale factor).
    # dst.width is already in our "inset" width space (510 at scale=1.0).
    scale = (float(dst.width) / 510.0) if float(dst.width) != 0.0 else 1.0
    top_h = MENU_PANEL_DST_TOP_H * scale
    bottom_h = MENU_PANEL_DST_BOTTOM_H * scale
    mid_h = float(dst.height) - top_h - bottom_h

    origin = rl.Vector2(0.0, 0.0)

    def _src(rect: rl.Rectangle) -> rl.Rectangle:
        if not flip_x:
            return rect
        return rl.Rectangle(rect.x + rect.width, rect.y, -rect.width, rect.height)

    if mid_h <= 0.0:
        src = _src(rl.Rectangle(src_x, src_y, src_w, src_h))
        if shadow:
            draw_ui_quad_shadow(
                texture=texture,
                src=src,
                dst=rl.Rectangle(
                    float(dst.x + UI_SHADOW_OFFSET),
                    float(dst.y + UI_SHADOW_OFFSET),
                    float(dst.width),
                    float(dst.height),
                ),
                origin=origin,
                rotation_deg=0.0,
            )
        rl.draw_texture_pro(texture, src, dst, origin, 0.0, tint)
        return

    # Source slice rects (in texture pixels, with 1px inset).
    src_top = _src(rl.Rectangle(src_x, src_y, src_w, max(0.0, MENU_PANEL_SRC_SLICE_Y1 - inset)))
    src_mid = _src(
        rl.Rectangle(src_x, MENU_PANEL_SRC_SLICE_Y1, src_w, max(0.0, MENU_PANEL_SRC_SLICE_Y2 - MENU_PANEL_SRC_SLICE_Y1))
    )
    src_bot = _src(rl.Rectangle(src_x, MENU_PANEL_SRC_SLICE_Y2, src_w, max(0.0, (tex_h - inset) - MENU_PANEL_SRC_SLICE_Y2)))

    # Destination slices.
    dst_top = rl.Rectangle(dst.x, dst.y, float(dst.width), float(top_h))
    dst_mid = rl.Rectangle(dst.x, dst.y + float(top_h), float(dst.width), float(mid_h))
    dst_bot = rl.Rectangle(dst.x, dst.y + float(top_h) + float(mid_h), float(dst.width), float(bottom_h))

    if shadow:
        draw_ui_quad_shadow(
            texture=texture,
            src=src_top,
            dst=rl.Rectangle(
                float(dst_top.x + UI_SHADOW_OFFSET),
                float(dst_top.y + UI_SHADOW_OFFSET),
                float(dst_top.width),
                float(dst_top.height),
            ),
            origin=origin,
            rotation_deg=0.0,
        )
        draw_ui_quad_shadow(
            texture=texture,
            src=src_mid,
            dst=rl.Rectangle(
                float(dst_mid.x + UI_SHADOW_OFFSET),
                float(dst_mid.y + UI_SHADOW_OFFSET),
                float(dst_mid.width),
                float(dst_mid.height),
            ),
            origin=origin,
            rotation_deg=0.0,
        )
        draw_ui_quad_shadow(
            texture=texture,
            src=src_bot,
            dst=rl.Rectangle(
                float(dst_bot.x + UI_SHADOW_OFFSET),
                float(dst_bot.y + UI_SHADOW_OFFSET),
                float(dst_bot.width),
                float(dst_bot.height),
            ),
            origin=origin,
            rotation_deg=0.0,
        )

    rl.draw_texture_pro(texture, src_top, dst_top, origin, 0.0, tint)
    rl.draw_texture_pro(texture, src_mid, dst_mid, origin, 0.0, tint)
    rl.draw_texture_pro(texture, src_bot, dst_bot, origin, 0.0, tint)
