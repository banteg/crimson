from __future__ import annotations

from grim.assets import TextureId
from grim.math import clamp

from ...projectiles.types import ProjectileTemplateId
from ..world.context import (
    draw_bullet_trail_quad,
    draw_late_bullet_pass_sprite,
    is_bullet_trail_type,
    late_bullet_pass_size,
)
from .common import proj_origin
from .types import ProjectileDrawCtx


def draw_bullet_trail(ctx: ProjectileDrawCtx) -> bool:
    renderer = ctx.renderer
    resources = renderer.frame.resources
    type_id = int(ctx.type_id)
    if not is_bullet_trail_type(type_id):
        return False

    drawn = False

    bullet_trail = resources.texture(TextureId.BULLET_TRAIL)
    if bullet_trail is not None:
        # Native Gauss color slots overwrite life*transition with clamped life.
        trail_alpha = clamp(float(ctx.life), 0.0, 1.0)
        if type_id != ProjectileTemplateId.GAUSS_GUN:
            trail_alpha *= float(ctx.alpha)
        origin = proj_origin(ctx.proj)
        drawn = draw_bullet_trail_quad(
            renderer,
            origin,
            ctx.pos,
            type_id=type_id,
            alpha=int(clamp(trail_alpha * 255.0, 0.0, 255.0)),
            velocity=ctx.proj.vel,
        )

    bullet = resources.texture(TextureId.BULLET_I)
    if bullet is not None and float(ctx.life) >= 0.39:
        draw_late_bullet_pass_sprite(
            bullet,
            screen_pos=ctx.screen_pos,
            size=late_bullet_pass_size(type_id, scale=ctx.scale),
            angle=ctx.angle,
            alpha=ctx.alpha,
        )
        drawn = True

    return bool(drawn)


__all__ = ["draw_bullet_trail"]
