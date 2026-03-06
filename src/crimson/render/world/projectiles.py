from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from ...perks import PerkId
from ...perks.helpers import perk_active
from ...sim.world_defs import KNOWN_PROJ_FRAMES
from ..projectile_draw import (
    ProjectileDrawCtx,
    SecondaryProjectileDrawCtx,
    draw_projectile_from_registry,
    draw_secondary_projectile_from_registry,
)
from ..projectile_render_registry import known_proj_rgb
from .context import WorldRenderCtx

if TYPE_CHECKING:
    from ...projectiles.types import Projectile, SecondaryProjectile


def draw_projectile(
    render_ctx: WorldRenderCtx,
    proj: Projectile,
    *,
    proj_index: int = 0,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return

    projectile_render_ctx = render_ctx.with_projection(camera=camera, view_scale=view_scale)
    texture = projectile_render_ctx.projs_texture
    type_id = proj.type_id
    proj_pos = proj.pos
    screen = projectile_render_ctx.world_to_screen(proj_pos)
    life = float(proj.life_timer)
    angle = float(proj.angle)

    registry_ctx = ProjectileDrawCtx(
        renderer=projectile_render_ctx,
        proj=proj,
        proj_index=int(proj_index),
        texture=texture,
        type_id=int(type_id),
        pos=proj_pos,
        screen_pos=screen,
        life=float(life),
        angle=float(angle),
        scale=float(scale),
        alpha=float(alpha),
    )
    if draw_projectile_from_registry(registry_ctx):
        return

    mapping = KNOWN_PROJ_FRAMES.get(type_id)
    if mapping is None:
        return
    if texture is None:
        if life < 0.39:
            return
        rl.draw_circle(
            int(screen.x),
            int(screen.y),
            max(1.0, 2.0 * scale),
            rl.Color(180, 180, 180, int(180 * alpha + 0.5)),
        )
        return

    grid, frame = mapping
    alpha_byte = int(clamp(clamp(life / 0.4, 0.0, 1.0) * 255.0 * alpha, 0.0, 255.0) + 0.5)
    red, green, blue = known_proj_rgb(type_id)
    tint = rl.Color(int(red), int(green), int(blue), alpha_byte)
    render_ctx._draw_atlas_sprite(
        texture,
        grid=grid,
        frame=frame,
        pos=screen,
        scale=0.6 * scale,
        rotation_rad=angle,
        tint=tint,
    )


def is_bullet_trail_type(type_id: int) -> bool:
    return WorldRenderCtx._is_bullet_trail_type(type_id)


def bullet_sprite_size(type_id: int, *, scale: float) -> float:
    return WorldRenderCtx._bullet_sprite_size(type_id, scale=scale)


def draw_bullet_trail(
    render_ctx: WorldRenderCtx,
    start: Vec2,
    end: Vec2,
    *,
    type_id: int,
    alpha: int,
    scale: float,
    angle: float,
) -> bool:
    return render_ctx._draw_bullet_trail(
        start,
        end,
        type_id=type_id,
        alpha=alpha,
        scale=scale,
        angle=angle,
    )


def draw_sharpshooter_laser_sight(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float,
) -> None:
    """Laser sight overlay for the Sharpshooter perk (`projectile_render` @ 0x00422c70)."""

    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return
    if render_ctx.bullet_trail_texture is None:
        return

    players = render_ctx.players
    if not players:
        return

    tail_alpha = int(clamp(alpha * 0.5, 0.0, 1.0) * 255.0 + 0.5)
    head_alpha = int(clamp(alpha * 0.2, 0.0, 1.0) * 255.0 + 0.5)
    tail = rl.Color(255, 0, 0, tail_alpha)
    head = rl.Color(255, 0, 0, head_alpha)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.rl_set_texture(render_ctx.bullet_trail_texture.id)
    rl.rl_begin(rd.RL_QUADS)

    for player in players:
        if float(player.health) <= 0.0:
            continue
        if not perk_active(player, PerkId.SHARPSHOOTER):
            continue
        player_pos = player.pos

        aim_heading = float(player.aim_heading)
        aim_dir = Vec2.from_heading(aim_heading)
        start = player_pos + aim_dir * 15.0
        end = player_pos + aim_dir * 512.0

        start_screen = render_ctx._world_to_screen_with(start, camera=camera, view_scale=view_scale)
        end_screen = render_ctx._world_to_screen_with(end, camera=camera, view_scale=view_scale)
        segment = end_screen - start_screen
        direction, dist = segment.normalized_with_length()
        if dist <= 1e-3:
            continue

        thickness = max(1.0, 2.0 * scale)
        half = thickness * 0.5
        side_offset = direction.perp_left() * half
        p0 = start_screen - side_offset
        p1 = start_screen + side_offset
        p2 = end_screen + side_offset
        p3 = end_screen - side_offset

        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(0.0, 0.0)
        rl.rl_vertex2f(p0.x, p0.y)
        rl.rl_color4ub(tail.r, tail.g, tail.b, tail.a)
        rl.rl_tex_coord2f(1.0, 0.0)
        rl.rl_vertex2f(p1.x, p1.y)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(1.0, 0.5)
        rl.rl_vertex2f(p2.x, p2.y)
        rl.rl_color4ub(head.r, head.g, head.b, head.a)
        rl.rl_tex_coord2f(0.0, 0.5)
        rl.rl_vertex2f(p3.x, p3.y)

    rl.rl_end()
    rl.rl_set_texture(0)
    rl.end_blend_mode()


def draw_secondary_projectile(
    render_ctx: WorldRenderCtx,
    proj: SecondaryProjectile,
    *,
    camera: Vec2,
    view_scale: Vec2,
    scale: float,
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return

    projectile_render_ctx = render_ctx.with_projection(camera=camera, view_scale=view_scale)
    proj_pos = proj.pos
    screen = projectile_render_ctx.world_to_screen(proj_pos)
    proj_type = proj.type_id
    angle = float(proj.angle)

    registry_ctx = SecondaryProjectileDrawCtx(
        renderer=projectile_render_ctx,
        proj=proj,
        proj_type=proj_type,
        screen_pos=screen,
        angle=float(angle),
        scale=float(scale),
        alpha=float(alpha),
    )
    if draw_secondary_projectile_from_registry(registry_ctx):
        return

    rl.draw_circle(
        int(screen.x),
        int(screen.y),
        max(1.0, 4.0 * scale),
        rl.Color(200, 200, 220, int(200 * alpha + 0.5)),
    )
