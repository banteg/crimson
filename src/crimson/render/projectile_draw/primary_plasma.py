from __future__ import annotations

import math

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from ...sim.world_defs import PLASMA_PARTICLE_TYPES
from ..projectile_render_registry import plasma_projectile_render_config
from .types import ProjectileDrawCtx


def draw_plasma_particles(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    if type_id not in PLASMA_PARTICLE_TYPES:
        return False
    if renderer.particles_texture is None:
        return False

    particles_texture = renderer.particles_texture
    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
    if atlas is None:
        return False
    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
    if not grid:
        return False

    cell_w = float(particles_texture.width) / float(grid)
    cell_h = float(particles_texture.height) / float(grid)
    frame = int(atlas.frame)
    col = frame % grid
    row = frame // grid
    src = rl.Rectangle(
        cell_w * float(col),
        cell_h * float(row),
        max(0.0, cell_w - 2.0),
        max(0.0, cell_h - 2.0),
    )

    speed_scale = float(getattr(ctx.proj, "speed_scale", 1.0))
    fx_detail_1 = renderer.config.fx_detail(level=1, default=True) if renderer.config is not None else True

    plasma_cfg = plasma_projectile_render_config(type_id)
    rgb = plasma_cfg.rgb
    spacing = plasma_cfg.spacing
    seg_limit = plasma_cfg.seg_limit
    tail_size = plasma_cfg.tail_size
    head_size = plasma_cfg.head_size
    head_alpha_mul = plasma_cfg.head_alpha_mul
    aura_rgb = plasma_cfg.aura_rgb
    aura_size = plasma_cfg.aura_size
    aura_alpha_mul = plasma_cfg.aura_alpha_mul

    if float(ctx.life) >= 0.4:
        # Reconstruct the tail length heuristic used by the native render path.
        seg_count = int(float(getattr(ctx.proj, "base_damage", 0.0)))
        if seg_count < 0:
            seg_count = 0
        seg_count //= 5
        if seg_count > int(seg_limit):
            seg_count = int(seg_limit)

        # The stored projectile angle is rotated by +pi/2 vs travel direction.
        direction = Vec2.from_heading(ctx.angle + math.pi) * speed_scale

        alpha = float(ctx.alpha)
        tail_tint = RGBA(rgb[0], rgb[1], rgb[2], alpha * 0.4).to_rl()
        head_tint = RGBA(rgb[0], rgb[1], rgb[2], alpha * head_alpha_mul).to_rl()
        aura_tint = RGBA(aura_rgb[0], aura_rgb[1], aura_rgb[2], alpha * aura_alpha_mul).to_rl()

        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)

        if seg_count > 0:
            size = float(tail_size) * ctx.scale
            origin = rl.Vector2(size * 0.5, size * 0.5)
            step = direction * float(spacing)
            for idx in range(int(seg_count)):
                pos = ctx.pos + step * float(idx)
                pos_screen = renderer.world_to_screen(pos)
                dst = rl.Rectangle(pos_screen.x, pos_screen.y, float(size), float(size))
                rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tail_tint)

        size = float(head_size) * ctx.scale
        origin = rl.Vector2(size * 0.5, size * 0.5)
        dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, float(size), float(size))
        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, head_tint)

        if fx_detail_1:
            size = float(aura_size) * ctx.scale
            origin = rl.Vector2(size * 0.5, size * 0.5)
            dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, float(size), float(size))
            rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, aura_tint)

        rl.end_blend_mode()
        return True

    fade = clamp(float(ctx.life) * 2.5, 0.0, 1.0)
    fade_alpha = fade * float(ctx.alpha)
    if fade_alpha > 1e-3:
        tint = RGBA(1.0, 1.0, 1.0, fade_alpha).to_rl()
        size = 56.0 * ctx.scale
        dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, float(size), float(size))
        origin = rl.Vector2(size * 0.5, size * 0.5)
        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)
        rl.end_blend_mode()

    return True


__all__ = ["draw_plasma_particles"]
