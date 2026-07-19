from __future__ import annotations

import msgspec

from grim.assets import TextureId
from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, SIZE_CODE_GRID, EffectId
from ...projectiles.types import SecondaryProjectileTypeId
from .types import SecondaryProjectileDrawCtx


class SecondaryRocketStyle(msgspec.Struct, frozen=True):
    base_size: float
    glow_size: float
    glow_rgb: tuple[float, float, float]
    glow_alpha_mul: float


_ROCKET_STYLE_BY_TYPE: dict[int, SecondaryRocketStyle] = {
    SecondaryProjectileTypeId.ROCKET: SecondaryRocketStyle(
        base_size=14.0,
        glow_size=60.0,
        glow_rgb=(1.0, 1.0, 1.0),
        glow_alpha_mul=0.68,
    ),
    SecondaryProjectileTypeId.HOMING_ROCKET: SecondaryRocketStyle(
        base_size=10.0,
        glow_size=40.0,
        glow_rgb=(1.0, 1.0, 1.0),
        glow_alpha_mul=0.58,
    ),
    SecondaryProjectileTypeId.ROCKET_MINIGUN: SecondaryRocketStyle(
        base_size=8.0,
        glow_size=30.0,
        glow_rgb=(0.7, 0.7, 1.0),
        glow_alpha_mul=0.158,
    ),
}


def draw_secondary_rocket(ctx: SecondaryProjectileDrawCtx) -> bool:
    style = _ROCKET_STYLE_BY_TYPE.get(ctx.proj_type)
    if style is None:
        return False

    renderer = ctx.renderer
    texture = renderer.frame.resources.texture(TextureId.PROJS)
    if texture is None:
        return False

    cell_w = texture.width / 4.0
    if cell_w <= 1e-6:
        return True

    alpha = ctx.alpha
    sprite_scale = (style.base_size * ctx.scale) / cell_w
    base_alpha = clamp(alpha * 0.9, 0.0, 1.0)
    base_tint = RGBA(0.8, 0.8, 0.8, base_alpha).to_rl()

    _draw_secondary_rocket_glow(ctx, style=style)

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


def draw_secondary_type4_fallback(ctx: SecondaryProjectileDrawCtx) -> bool:
    if ctx.proj_type != SecondaryProjectileTypeId.ROCKET_MINIGUN:
        return False
    rl.draw_circle(
        int(ctx.screen_pos.x),
        int(ctx.screen_pos.y),
        max(1.0, 12.0 * ctx.scale),
        rl.Color(200, 120, 255, int(255 * ctx.alpha + 0.5)),
    )
    return True


def draw_secondary_projectile_bloom(ctx: SecondaryProjectileDrawCtx) -> None:
    """Render projectile_render's shared 140px secondary-projectile pass."""

    renderer = ctx.renderer
    render_frame = renderer.frame
    fx_detail_1 = (
        render_frame.config.display.fx_detail_enabled(level=1, default=True) if render_frame.config is not None else True
    )
    particles_texture = render_frame.resources.texture(TextureId.PARTICLES)
    if not fx_detail_1 or particles_texture is None:
        return

    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
    if atlas is None:
        return
    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
    if not grid:
        return

    frame = int(atlas.frame)
    col = frame % grid
    row = frame // grid
    particle_cell_w = particles_texture.width / grid
    particle_cell_h = particles_texture.height / grid
    src = rl.Rectangle(
        particle_cell_w * col,
        particle_cell_h * row,
        max(0.0, particle_cell_w - 2.0),
        max(0.0, particle_cell_h - 2.0),
    )

    direction = Vec2.from_heading(ctx.angle)
    dst_size = 140.0 * ctx.scale
    fx_pos = ctx.screen_pos - direction * (5.0 * ctx.scale)
    dst = rl.Rectangle(fx_pos.x, fx_pos.y, dst_size, dst_size)
    origin = rl.Vector2(dst_size * 0.5, dst_size * 0.5)
    tint = RGBA(1.0, 1.0, 1.0, ctx.alpha * 0.48).to_rl()

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.draw_texture_pro(particles_texture, src, dst, origin, 0.0, tint)
    rl.end_blend_mode()


def _draw_secondary_rocket_glow(ctx: SecondaryProjectileDrawCtx, *, style: SecondaryRocketStyle) -> None:
    renderer = ctx.renderer
    render_frame = renderer.frame
    fx_detail_1 = (
        render_frame.config.display.fx_detail_enabled(level=1, default=True) if render_frame.config is not None else True
    )
    particles_texture = render_frame.resources.texture(TextureId.PARTICLES)
    if not fx_detail_1 or particles_texture is None:
        return

    atlas = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(EffectId.GLOW))
    if atlas is None:
        return
    grid = SIZE_CODE_GRID.get(int(atlas.size_code))
    if not grid:
        return

    frame = int(atlas.frame)
    col = frame % grid
    row = frame // grid
    particle_cell_w = particles_texture.width / grid
    particle_cell_h = particles_texture.height / grid
    src = rl.Rectangle(
        particle_cell_w * col,
        particle_cell_h * row,
        max(0.0, particle_cell_w - 2.0),
        max(0.0, particle_cell_h - 2.0),
    )

    direction = Vec2.from_heading(ctx.angle)
    scale = ctx.scale
    alpha = ctx.alpha

    def draw_rocket_fx(
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
    glow_r, glow_g, glow_b = style.glow_rgb
    draw_rocket_fx(
        size=style.glow_size,
        offset=9.0,
        rgba=RGBA(glow_r, glow_g, glow_b, alpha * style.glow_alpha_mul),
    )
    rl.end_blend_mode()


__all__ = [
    "draw_secondary_projectile_bloom",
    "draw_secondary_rocket",
    "draw_secondary_type4_fallback",
]
