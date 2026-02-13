from __future__ import annotations

import pyray as rl

from grim.math import clamp

from .common import RAD_TO_DEG, proj_origin
from .types import ProjectileDrawCtx


def draw_bullet_trail(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    type_id = int(ctx.type_id)
    if not renderer._is_bullet_trail_type(type_id):
        return False

    life_alpha = int(clamp(float(ctx.life), 0.0, 1.0) * 255.0)
    alpha_byte = int(clamp(float(life_alpha) * float(ctx.alpha), 0.0, 255.0) + 0.5)
    drawn = False

    if renderer.bullet_trail_texture is not None:
        origin = proj_origin(ctx.proj, ctx.pos)
        origin_screen = renderer.world_to_screen(origin)
        drawn = renderer._draw_bullet_trail(
            origin_screen,
            ctx.screen_pos,
            type_id=type_id,
            alpha=alpha_byte,
            scale=ctx.scale,
            angle=ctx.angle,
        )

    if renderer.bullet_texture is not None and float(ctx.life) >= 0.39:
        size = renderer._bullet_sprite_size(type_id, scale=ctx.scale)
        src = rl.Rectangle(0.0, 0.0, float(renderer.bullet_texture.width), float(renderer.bullet_texture.height))
        dst = rl.Rectangle(ctx.screen_pos.x, ctx.screen_pos.y, float(size), float(size))
        origin = rl.Vector2(float(size) * 0.5, float(size) * 0.5)
        tint = rl.Color(220, 220, 220, int(alpha_byte))
        rl.draw_texture_pro(renderer.bullet_texture, src, dst, origin, ctx.angle * RAD_TO_DEG, tint)
        drawn = True

    return bool(drawn)


__all__ = ["draw_bullet_trail"]
