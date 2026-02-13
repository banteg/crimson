from __future__ import annotations

import pyray as rl

from grim.color import RGBA
from grim.math import clamp

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from .types import SecondaryProjectileDrawCtx


def draw_secondary_type4_fallback(ctx: SecondaryProjectileDrawCtx) -> bool:
    if int(ctx.proj_type) != 4:
        return False
    rl.draw_circle(
        int(ctx.screen_pos.x),
        int(ctx.screen_pos.y),
        max(1.0, 12.0 * ctx.scale),
        rl.Color(200, 120, 255, int(255 * ctx.alpha + 0.5)),
    )
    return True


def draw_secondary_detonation(ctx: SecondaryProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    if int(ctx.proj_type) != 3:
        return False

    # Secondary projectile detonation visuals (secondary_projectile_update + render).
    t = clamp(float(getattr(ctx.proj, "detonation_t", 0.0)), 0.0, 1.0)
    det_scale = float(getattr(ctx.proj, "detonation_scale", 1.0))
    fade = (1.0 - t) * ctx.alpha
    if fade <= 1e-3 or det_scale <= 1e-6:
        return True

    scale = ctx.scale
    particles_texture = renderer.particles_texture
    if particles_texture is None:
        radius = det_scale * t * 80.0
        alpha_byte = int(clamp((1.0 - t) * 180.0 * ctx.alpha, 0.0, 255.0) + 0.5)
        color = rl.Color(255, 180, 100, alpha_byte)
        rl.draw_circle_lines(int(ctx.screen_pos.x), int(ctx.screen_pos.y), max(1.0, radius * scale), color)
        return True

    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
    if atlas is None:
        return True
    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
    if not grid:
        return True
    frame = int(atlas.frame)
    col = frame % grid
    row = frame // grid
    cell_w = particles_texture.width / grid
    cell_h = particles_texture.height / grid
    src = rl.Rectangle(
        cell_w * col,
        cell_h * row,
        max(0.0, cell_w - 2.0),
        max(0.0, cell_h - 2.0),
    )

    def draw_detonation_quad(*, size: float, alpha_mul: float) -> None:
        a = fade * alpha_mul
        if a <= 1e-3:
            return
        dst_size = size * scale
        if dst_size <= 1e-3:
            return
        tint = RGBA(1.0, 0.6, 0.1, a).to_rl()
        dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, dst_size, dst_size)
        origin = rl.Vector2(dst_size * 0.5, dst_size * 0.5)
        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    draw_detonation_quad(size=det_scale * t * 64.0, alpha_mul=1.0)
    draw_detonation_quad(size=det_scale * t * 200.0, alpha_mul=0.3)
    rl.end_blend_mode()
    return True


__all__ = ["draw_secondary_detonation", "draw_secondary_type4_fallback"]
