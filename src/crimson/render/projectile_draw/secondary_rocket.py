from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp

from ...effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId, SIZE_CODE_GRID
from .types import SecondaryProjectileDrawCtx


@dataclass(frozen=True, slots=True)
class SecondaryRocketStyle:
    base_size: float
    glow_size: float
    glow_rgb: tuple[float, float, float]
    glow_alpha_mul: float


_ROCKET_STYLE_BY_TYPE: dict[int, SecondaryRocketStyle] = {
    1: SecondaryRocketStyle(
        base_size=14.0,
        glow_size=60.0,
        glow_rgb=(1.0, 1.0, 1.0),
        glow_alpha_mul=0.68,
    ),
    2: SecondaryRocketStyle(
        base_size=10.0,
        glow_size=40.0,
        glow_rgb=(1.0, 1.0, 1.0),
        glow_alpha_mul=0.58,
    ),
    4: SecondaryRocketStyle(
        base_size=8.0,
        glow_size=30.0,
        glow_rgb=(0.7, 0.7, 1.0),
        glow_alpha_mul=0.158,
    ),
}


def draw_secondary_rocket(ctx: SecondaryProjectileDrawCtx) -> bool:
    style = _ROCKET_STYLE_BY_TYPE.get(int(ctx.proj_type))
    if style is None:
        return False

    renderer = ctx.renderer
    texture = renderer.projs_texture
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
    if int(ctx.proj_type) != 4:
        return False
    rl.draw_circle(
        int(ctx.screen_pos.x),
        int(ctx.screen_pos.y),
        max(1.0, 12.0 * ctx.scale),
        rl.Color(200, 120, 255, int(255 * ctx.alpha + 0.5)),
    )
    return True


def _draw_secondary_rocket_glow(ctx: SecondaryProjectileDrawCtx, *, style: SecondaryRocketStyle) -> None:
    renderer = ctx.renderer
    fx_detail_1 = renderer.config.fx_detail(level=1, default=True) if renderer.config is not None else True
    particles_texture = renderer.particles_texture
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
    # Large bloom around the rocket (effect_id=0x0D).
    draw_rocket_fx(size=140.0, offset=5.0, rgba=RGBA(1.0, 1.0, 1.0, alpha * 0.48))

    glow_r, glow_g, glow_b = style.glow_rgb
    draw_rocket_fx(
        size=style.glow_size,
        offset=9.0,
        rgba=RGBA(glow_r, glow_g, glow_b, alpha * style.glow_alpha_mul),
    )
    rl.end_blend_mode()


__all__ = ["draw_secondary_rocket", "draw_secondary_type4_fallback"]
