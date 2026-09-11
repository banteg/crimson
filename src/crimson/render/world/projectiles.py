from __future__ import annotations

from typing import TYPE_CHECKING

from grim.assets import TextureId
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from ...math_parity import NATIVE_HALF_PI, f32, f32_vec2, sin_f32, x87_pc24_cos_mul, x87_pc24_sin_mul
from ...perks import PerkId
from ...perks.helpers import perk_active
from ...projectiles.types import ProjectileTemplateId
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
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    # Native Gauss trail slots use life alpha even when the world transition is zero.
    if alpha <= 1e-3 and proj.type_id != ProjectileTemplateId.GAUSS_GUN:
        return

    scale = render_ctx.view.scale
    texture = render_ctx.frame.resources.texture(TextureId.PROJS)
    type_id = proj.type_id
    proj_pos = proj.pos
    screen = render_ctx.world_to_screen(proj_pos)
    life = float(proj.life_timer)
    angle = float(proj.angle)

    registry_ctx = ProjectileDrawCtx(
        renderer=render_ctx,
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


def _sharpshooter_laser_corners(
    player_pos: Vec2,
    aim_heading: float,
    *,
    camera: Vec2,
) -> tuple[Vec2, Vec2, Vec2, Vec2]:
    """Preserve the native laser's trig products and PC24 corner stores."""

    player_pos = f32_vec2(player_pos)
    aim_heading = f32(aim_heading)
    heading = f32(aim_heading - NATIVE_HALF_PI)
    # Native keeps the far cosine wide, but stores its sine before scaling.
    end = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(heading, 512.0), f32(sin_f32(heading) * 512.0)),
    )
    start_heading = f32(heading - f32(0.150915))
    start = f32_vec2(
        player_pos + Vec2(x87_pc24_cos_mul(start_heading, 15.0), x87_pc24_sin_mul(start_heading, 15.0)),
    )
    half_width = Vec2(
        x87_pc24_cos_mul(aim_heading, f32(1.1)),
        x87_pc24_sin_mul(aim_heading, f32(1.1)),
    )
    camera = f32_vec2(camera)
    start = f32_vec2(start + camera)
    end = f32_vec2(end + camera)
    return (
        f32_vec2(start - half_width),
        f32_vec2(start + half_width),
        f32_vec2(end + half_width),
        f32_vec2(end - half_width),
    )


def draw_sharpshooter_laser_sight(
    render_ctx: WorldRenderCtx,
    *,
    camera: Vec2,
    view_scale: Vec2,
    alpha: float,
) -> None:
    """Laser sight overlay for the Sharpshooter perk (`projectile_render` @ 0x00422c70)."""

    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return
    bullet_trail_texture = render_ctx.frame.resources.texture(TextureId.BULLET_TRAIL)

    players = render_ctx.frame.players
    if not players:
        return

    alpha = f32(alpha)
    # Grim truncates each scaled float channel; the far slots are black.
    tail_alpha = int(f32(f32(alpha * 0.5) * 255.0))
    head_alpha = int(f32(f32(alpha * f32(0.2)) * 255.0))
    tail = rl.Color(255, 0, 0, tail_alpha)
    head = rl.Color(0, 0, 0, head_alpha)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.rl_set_texture(bullet_trail_texture.id)
    rl.rl_begin(rd.RL_QUADS)

    for player in players:
        if float(player.health) <= 0.0:
            continue
        # Native 0x422ea8 reads player zero even when drawing another player.
        perk_owner = players[0] if render_ctx.frame.state.preserve_bugs else player
        if not perk_active(perk_owner, PerkId.SHARPSHOOTER):
            continue
        corners = _sharpshooter_laser_corners(player.pos, player.aim_heading, camera=camera)
        p0, p1, p2, p3 = (point.mul_components(view_scale) for point in corners)

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
    alpha: float = 1.0,
) -> None:
    alpha = clamp(float(alpha), 0.0, 1.0)
    if alpha <= 1e-3:
        return

    scale = render_ctx.view.scale
    proj_pos = proj.pos
    screen = render_ctx.world_to_screen(proj_pos)
    proj_type = proj.type_id
    angle = float(proj.angle)

    registry_ctx = SecondaryProjectileDrawCtx(
        renderer=render_ctx,
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
