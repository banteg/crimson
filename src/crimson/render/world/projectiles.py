from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rd, rl

from ...perks import PerkId
from ...perks.helpers import perk_active
from ...projectiles import ProjectileTypeId
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
    from ...projectiles import Projectile, SecondaryProjectile
    from ..projectile_draw import ProjectileRendererLike
    from ..rtx.mode import RtxRenderMode


@dataclass(slots=True)
class _ProjectileRendererAdapter:
    render_ctx: WorldRenderCtx
    camera: Vec2
    view_scale: Vec2

    @property
    def bullet_trail_texture(self) -> rl.Texture | None:
        return self.render_ctx.bullet_trail_texture

    @property
    def bullet_texture(self) -> rl.Texture | None:
        return self.render_ctx.bullet_texture

    @property
    def particles_texture(self) -> rl.Texture | None:
        return self.render_ctx.particles_texture

    @property
    def projs_texture(self) -> rl.Texture | None:
        return self.render_ctx.projs_texture

    @property
    def config(self):
        return self.render_ctx.config

    @property
    def players(self):
        return self.render_ctx.players

    @property
    def creatures(self):
        return self.render_ctx.creatures

    @property
    def elapsed_ms(self) -> float:
        return self.render_ctx.elapsed_ms

    @property
    def rtx_mode(self) -> "RtxRenderMode":
        return self.render_ctx.rtx_mode

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return is_bullet_trail_type(type_id)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.render_ctx._world_to_screen_with(pos, camera=self.camera, view_scale=self.view_scale)

    def _draw_bullet_trail(
        self,
        start: Vec2,
        end: Vec2,
        *,
        type_id: int,
        alpha: int,
        scale: float,
        angle: float,
    ) -> bool:
        return draw_bullet_trail(
            self.render_ctx,
            start,
            end,
            type_id=type_id,
            alpha=alpha,
            scale=scale,
            angle=angle,
        )

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        return bullet_sprite_size(type_id, scale=scale)

    def _draw_atlas_sprite(
        self,
        texture: rl.Texture,
        *,
        grid: int,
        frame: int,
        pos: Vec2,
        scale: float,
        rotation_rad: float = 0.0,
        tint: rl.Color = rl.WHITE,
    ) -> None:
        self.render_ctx._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            pos=pos,
            scale=scale,
            rotation_rad=rotation_rad,
            tint=tint,
        )


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

    texture = render_ctx.projs_texture
    type_id = int(proj.type_id)
    proj_pos = proj.pos
    screen = render_ctx._world_to_screen_with(proj_pos, camera=camera, view_scale=view_scale)
    life = float(proj.life_timer)
    angle = float(proj.angle)

    adapter = _ProjectileRendererAdapter(render_ctx, camera=camera, view_scale=view_scale)
    registry_ctx = ProjectileDrawCtx(
        renderer=cast("ProjectileRendererLike", adapter),
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
    return 0 <= type_id < 8 or type_id == int(ProjectileTypeId.SPLITTER_GUN)


def bullet_sprite_size(type_id: int, *, scale: float) -> float:
    base = 4.0
    if type_id == int(ProjectileTypeId.ASSAULT_RIFLE):
        base = 6.0
    elif type_id == int(ProjectileTypeId.SUBMACHINE_GUN):
        base = 8.0
    return max(2.0, base * scale)


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
    if render_ctx.bullet_trail_texture is None:
        return False
    if alpha <= 0:
        return False

    segment = end - start
    direction, dist = segment.normalized_with_length()

    # Native uses projectile travel direction as the side-offset basis and still emits the
    # trail quad even when origin=head (degenerate impact frames).
    if type_id in (int(ProjectileTypeId.PISTOL), int(ProjectileTypeId.ASSAULT_RIFLE)):
        side_mul = 1.2
    elif type_id == int(ProjectileTypeId.GAUSS_GUN):
        side_mul = 1.1
    else:
        side_mul = 0.7
    half = 1.5 * side_mul * scale

    if dist > 1e-6:
        side = direction.perp_left()
    else:
        side = Vec2.from_angle(angle)

    side_offset = side * half
    p0 = start - side_offset
    p1 = start + side_offset
    p2 = end + side_offset
    p3 = end - side_offset

    # Native uses additive blending for bullet trails and sets color slots per projectile type.
    # Gauss has a distinct blue tint; most other bullet trails are neutral gray.
    if type_id == int(ProjectileTypeId.GAUSS_GUN):
        head_rgb = (51, 128, 255)  # (0.2, 0.5, 1.0)
    else:
        head_rgb = (128, 128, 128)  # (0.5, 0.5, 0.5)

    tail_rgb = (128, 128, 128)
    head = rl.Color(head_rgb[0], head_rgb[1], head_rgb[2], alpha)
    tail = rl.Color(tail_rgb[0], tail_rgb[1], tail_rgb[2], 0)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.rl_set_texture(render_ctx.bullet_trail_texture.id)
    rl.rl_begin(rd.RL_QUADS)
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
    return True


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

    proj_pos = proj.pos
    screen = render_ctx._world_to_screen_with(proj_pos, camera=camera, view_scale=view_scale)
    proj_type = int(proj.type_id)
    angle = float(proj.angle)

    adapter = _ProjectileRendererAdapter(render_ctx, camera=camera, view_scale=view_scale)
    registry_ctx = SecondaryProjectileDrawCtx(
        renderer=cast("ProjectileRendererLike", adapter),
        proj=proj,
        proj_type=int(proj_type),
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
