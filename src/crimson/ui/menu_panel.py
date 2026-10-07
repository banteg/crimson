from __future__ import annotations

from grim.assets import RuntimeResources, TextureId
from grim.geom import Rect, Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2

from .animation import ui_element_anim, ui_element_direction_flag
from .menu_layout import MENU_PANEL_WIDTH, ui_element_pos
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

    origin = rl_vector2(0.0, 0.0)

    def _src(rect: rl.Rectangle) -> rl.Rectangle:
        if not flip_x:
            return rect
        # Use negative source width to mirror the panel, but keep src.x in-range.
        #
        # With CLAMP wrap, raylib's DrawTexturePro behaves badly when flipping via
        # src.x=rect.x+rect.width (u near 1.0) and negative widths; it can clamp
        # the UVs to the edge texel and collapse the panel to a transparent strip.
        return rl_rectangle(rect.x, rect.y, -rect.width, rect.height)

    if mid_h <= 0.0:
        src = _src(rl_rectangle(src_x, src_y, src_w, src_h))
        if shadow:
            draw_ui_quad_shadow(
                texture=texture,
                src=src,
                dst=rl_rectangle(
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
    src_top = _src(rl_rectangle(src_x, src_y, src_w, max(0.0, MENU_PANEL_SRC_SLICE_Y1 - inset)))
    src_mid = _src(
        rl_rectangle(src_x, MENU_PANEL_SRC_SLICE_Y1, src_w, max(0.0, MENU_PANEL_SRC_SLICE_Y2 - MENU_PANEL_SRC_SLICE_Y1)),
    )
    src_bot = _src(rl_rectangle(src_x, MENU_PANEL_SRC_SLICE_Y2, src_w, max(0.0, (tex_h - inset) - MENU_PANEL_SRC_SLICE_Y2)))

    # Destination slices.
    dst_top = rl_rectangle(dst.x, dst.y, float(dst.width), float(top_h))
    dst_mid = rl_rectangle(dst.x, dst.y + float(top_h), float(dst.width), float(mid_h))
    dst_bot = rl_rectangle(dst.x, dst.y + float(top_h) + float(mid_h), float(dst.width), float(bottom_h))

    if shadow:
        draw_ui_quad_shadow(
            texture=texture,
            src=src_top,
            dst=rl_rectangle(
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
            dst=rl_rectangle(
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
            dst=rl_rectangle(
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


def ui_panel_rect(index: int, timeline_ms: float, screen_width: float) -> Rect:
    """`ui_element_render` of the panel `ui_element_table[index]`: its quads at the element position plus the
    `ui_element_update` slide.

    `ui_menu_assets_init` sets ui_menuPanel as a 512x256 quad at (20, -82) inset a pixel; `ui_menuPanelTall` moves it
    84 left and stretches it 124 taller in three slices, and a second copy is 100 shorter than that.
    """
    match index:
        case 14 | 31 | 33:
            first_vertex, height = Vec2(21.0, -81.0), 254.0
        case 11:
            first_vertex, height = Vec2(-63.0, -81.0), 278.0
        case _:
            first_vertex, height = Vec2(-63.0, -81.0), 378.0
    slide_x = ui_element_anim(timeline_ms, index=index, width=MENU_PANEL_WIDTH)[1]
    top_left = ui_element_pos(index, screen_width) + first_vertex
    return Rect.from_top_left(top_left.offset(dx=slide_x), MENU_PANEL_WIDTH, height)


def draw_ui_panel(resources: RuntimeResources, index: int, rect: Rect, *, shadow: bool) -> None:
    """Draw the panel element `index` at `rect` (from `ui_panel_rect`); flipped elements mirror it."""
    draw_classic_menu_panel(
        resources.texture(TextureId.UI_MENU_PANEL),
        dst=rect.to_rl(),
        shadow=shadow,
        flip_x=ui_element_direction_flag(index),
    )
