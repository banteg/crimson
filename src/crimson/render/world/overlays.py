from __future__ import annotations

from grim.assets import TextureId
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from . import viewport
from .constants import _RAD_TO_DEG
from .context import WorldRenderCtx


def grim2d_circle_segments_filled(radius: float) -> int:
    # grim_draw_circle_filled (grim.dll): segments = trunc(radius * 0.125 + 12.0)
    return max(3, int(radius * 0.125 + 12.0))


def grim2d_circle_segments_outline(radius: float) -> int:
    # grim_draw_circle_outline (grim.dll): segments = trunc(radius * 0.2 + 14.0)
    return max(3, int(radius * 0.2 + 14.0))


def draw_aim_circle(render_ctx: WorldRenderCtx, *, center: Vec2, radius: float, alpha: float = 1.0) -> None:
    if radius <= 1e-3:
        return
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return

    fill_a = int(77 * alpha + 0.5)  # ui_render_aim_indicators: rgba(0,0,0.1,0.3)
    outline_a = int(255 * 0.55 * alpha + 0.5)
    fill = rl.Color(0, 0, 26, fill_a)
    outline = rl.Color(255, 255, 255, outline_a)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ALPHA)

    # The original uses a triangle fan (polygons). Raylib provides circle
    # primitives that still use triangles internally, but allow higher
    # segment counts for a smoother result when scaled.
    seg_count = max(grim2d_circle_segments_filled(radius), 64, int(radius))
    center_rl = center.to_rl()
    rl.draw_circle_sector(center_rl, float(radius), 0.0, 360.0, int(seg_count), fill)

    seg_count = max(grim2d_circle_segments_outline(radius), int(seg_count))
    # grim_draw_circle_outline draws a 2px-thick ring (outer radius = r + 2).
    # The exe binds bulletTrail, but that texture is white; the visual intent is
    # a subtle white outline around the filled spread circle.
    rl.draw_ring(center_rl, float(radius), float(radius + 2.0), 0.0, 360.0, int(seg_count), outline)

    rl.rl_set_texture(0)
    rl.end_blend_mode()


def draw_clock_gauge(
    render_ctx: WorldRenderCtx,
    *,
    pos: Vec2,
    ms: int,
    scale: float,
    alpha: float = 1.0,
) -> None:
    resources = render_ctx.frame.resources
    table = resources.texture(TextureId.UI_CLOCK_TABLE)
    pointer = resources.texture(TextureId.UI_CLOCK_POINTER)
    size = 32.0 * scale
    if size <= 1e-3:
        return
    tint = rl.Color(255, 255, 255, int(clamp(float(alpha), 0.0, 1.0) * 255.0 + 0.5))
    half = size * 0.5

    table_src = rl.Rectangle(
        0.0,
        0.0,
        float(table.width),
        float(table.height),
    )
    table_dst = rl.Rectangle(pos.x, pos.y, size, size)
    rl.draw_texture_pro(table, table_src, table_dst, rl.Vector2(0.0, 0.0), 0.0, tint)

    seconds = int(ms) // 1000
    pointer_src = rl.Rectangle(
        0.0,
        0.0,
        float(pointer.width),
        float(pointer.height),
    )
    pointer_dst = rl.Rectangle(pos.x + half, pos.y + half, size, size)
    origin = rl.Vector2(half, half)
    rotation_deg = float(seconds) * 6.0
    rl.draw_texture_pro(pointer, pointer_src, pointer_dst, origin, rotation_deg, tint)


def direction_arrow_enabled(render_ctx: WorldRenderCtx, player_index: int) -> bool:
    config = render_ctx.frame.config
    if config is None:
        return True
    return config.controls.player(player_index).show_direction_arrow


def direction_arrow_tint(render_ctx: WorldRenderCtx, player_index: int, *, alpha: float) -> rl.Color:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if len(render_ctx.frame.players) == 2:
        if int(player_index) == 0:
            return rl.Color(204, 230, 255, int(153.0 * alpha + 0.5))
        return rl.Color(255, 230, 204, int(153.0 * alpha + 0.5))
    return rl.Color(255, 255, 255, int(77.0 * alpha + 0.5))


def draw_direction_arrows(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return
    arrow = render_ctx.frame.resources.texture(TextureId.ARROW)

    src = rl.Rectangle(0.0, 0.0, float(arrow.width), float(arrow.height))
    width = max(1.0, float(arrow.width) * scale)
    height = max(1.0, float(arrow.height) * scale)
    origin = rl.Vector2(width * 0.5, height * 0.5)

    for player in render_ctx.frame.players:
        if float(player.health) <= 0.0:
            continue
        index = int(player.index)
        if not direction_arrow_enabled(render_ctx, index):
            continue

        heading = float(player.heading)
        marker_pos = player.pos + Vec2.from_heading(heading) * 60.0
        screen = viewport.world_to_screen_with(marker_pos, camera=camera, view_scale=view_scale)
        dst = rl.Rectangle(screen.x, screen.y, width, height)
        tint = direction_arrow_tint(render_ctx, index, alpha=alpha)
        rl.draw_texture_pro(arrow, src, dst, origin, float(heading * _RAD_TO_DEG), tint)
