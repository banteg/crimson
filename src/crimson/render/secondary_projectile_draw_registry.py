from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp

from ..effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID

if TYPE_CHECKING:
    from ..projectiles import SecondaryProjectile
    from .world_renderer import WorldRenderer


@dataclass(frozen=True, slots=True)
class SecondaryProjectileDrawCtx:
    renderer: WorldRenderer
    proj: SecondaryProjectile
    proj_type: int
    screen_pos: Vec2
    angle: float
    scale: float
    alpha: float


def _draw_secondary_rocket_like(ctx: SecondaryProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    proj_type = int(ctx.proj_type)
    if proj_type not in (1, 2, 4):
        return False

    texture = renderer.projs_texture
    if texture is None:
        return False

    cell_w = texture.width / 4.0
    if cell_w <= 1e-6:
        return True

    alpha = ctx.alpha
    base_alpha = clamp(alpha * 0.9, 0.0, 1.0)
    base_tint = RGBA(0.8, 0.8, 0.8, base_alpha).to_rl()
    base_size = 14.0
    if proj_type == 2:
        base_size = 10.0
    elif proj_type == 4:
        base_size = 8.0
    sprite_scale = (base_size * ctx.scale) / cell_w

    fx_detail_1 = bool(renderer.config.data.get("fx_detail_1", 0)) if renderer.config is not None else True
    if fx_detail_1 and renderer.particles_texture is not None:
        particles_texture = renderer.particles_texture
        atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
        if atlas is not None:
            grid = SIZE_CODE_GRID.get(int(atlas.size_code))
            if grid:
                particle_cell_w = particles_texture.width / grid
                particle_cell_h = particles_texture.height / grid
                frame = int(atlas.frame)
                col = frame % grid
                row = frame // grid
                src = rl.Rectangle(
                    particle_cell_w * col,
                    particle_cell_h * row,
                    max(0.0, particle_cell_w - 2.0),
                    max(0.0, particle_cell_h - 2.0),
                )

                direction = Vec2.from_heading(ctx.angle)

                scale = ctx.scale

                def _draw_rocket_fx(
                    *,
                    size: float,
                    offset: float,
                    rgba: RGBA,
                ) -> None:
                    fx_alpha = rgba.a
                    if fx_alpha <= 1e-3:
                        return
                    tint = rgba.to_rl()
                    fx_pos = ctx.screen_pos - direction * (offset * scale)
                    dst_size = size * scale
                    dst = rl.Rectangle(fx_pos.x, fx_pos.y, dst_size, dst_size)
                    origin = rl.Vector2(dst_size * 0.5, dst_size * 0.5)
                    rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)

                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                # Large bloom around the rocket (effect_id=0x0D).
                _draw_rocket_fx(size=140.0, offset=5.0, rgba=RGBA(1.0, 1.0, 1.0, alpha * 0.48))

                if proj_type == 4:
                    _draw_rocket_fx(size=30.0, offset=9.0, rgba=RGBA(0.7, 0.7, 1.0, alpha * 0.158))
                elif proj_type == 2:
                    _draw_rocket_fx(size=40.0, offset=9.0, rgba=RGBA(1.0, 1.0, 1.0, alpha * 0.58))
                else:
                    _draw_rocket_fx(size=60.0, offset=9.0, rgba=RGBA(1.0, 1.0, 1.0, alpha * 0.68))

                rl.end_blend_mode()

    renderer._draw_atlas_sprite(
        texture,
        grid=4,
        frame=3,
        pos=ctx.screen_pos,
        scale=sprite_scale,
        rotation_rad=ctx.angle,
        tint=base_tint,
    )
    return True


def _draw_secondary_type4_fallback(ctx: SecondaryProjectileDrawCtx) -> bool:
    if int(ctx.proj_type) != 4:
        return False
    rl.draw_circle(
        int(ctx.screen_pos.x),
        int(ctx.screen_pos.y),
        max(1.0, 12.0 * ctx.scale),
        rl.Color(200, 120, 255, int(255 * ctx.alpha + 0.5)),
    )
    return True


def _draw_secondary_detonation(ctx: SecondaryProjectileDrawCtx) -> bool:
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

    def _draw_detonation_quad(*, size: float, alpha_mul: float) -> None:
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
    _draw_detonation_quad(size=det_scale * t * 64.0, alpha_mul=1.0)
    _draw_detonation_quad(size=det_scale * t * 200.0, alpha_mul=0.3)
    rl.end_blend_mode()
    return True


SECONDARY_PROJECTILE_DRAW_HANDLERS = (
    _draw_secondary_rocket_like,
    _draw_secondary_type4_fallback,
    _draw_secondary_detonation,
)


def draw_secondary_projectile_from_registry(ctx: SecondaryProjectileDrawCtx) -> bool:
    for handler in SECONDARY_PROJECTILE_DRAW_HANDLERS:
        if handler(ctx):
            return True
    return False
