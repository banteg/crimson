from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pyray as rl
from raylib import defines as rd

from grim.geom import Vec2
from grim.math import clamp

from ...perks import PerkId
from ...perks.helpers import perk_active
from ...projectiles import ProjectileTypeId
from ...sim.world_defs import KNOWN_PROJ_FRAMES
from ..projectile_draw_registry import ProjectileDrawCtx, draw_projectile_from_registry
from ..projectile_render_registry import known_proj_rgb
from ..secondary_projectile_draw_registry import SecondaryProjectileDrawCtx, draw_secondary_projectile_from_registry
from .mixin_base import WorldRendererMixinBase

if TYPE_CHECKING:
    from ...projectiles import Projectile, SecondaryProjectile
    from .renderer import WorldRenderer


class WorldRendererProjectilesMixin(WorldRendererMixinBase):
    def _draw_projectile(self, proj: Projectile, *, proj_index: int = 0, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        texture = self.projs_texture
        type_id = int(proj.type_id)
        proj_pos = proj.pos
        screen = self.world_to_screen(proj_pos)
        life = float(proj.life_timer)
        angle = float(proj.angle)

        ctx = ProjectileDrawCtx(
            renderer=cast("WorldRenderer", self),
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
        if draw_projectile_from_registry(ctx):
            return

        mapping = KNOWN_PROJ_FRAMES.get(type_id)
        if mapping is None:
            return
        if texture is None:
            if life < 0.39:
                return
            rl.draw_circle(
                int(screen.x), int(screen.y), max(1.0, 2.0 * scale), rl.Color(180, 180, 180, int(180 * alpha + 0.5))
            )
            return
        grid, frame = mapping

        alpha_byte = int(clamp(clamp(life / 0.4, 0.0, 1.0) * 255.0 * alpha, 0.0, 255.0) + 0.5)
        r, g, b = known_proj_rgb(type_id)
        tint = rl.Color(int(r), int(g), int(b), alpha_byte)
        self._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            pos=screen,
            scale=0.6 * scale,
            rotation_rad=angle,
            tint=tint,
        )

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return 0 <= type_id < 8 or type_id == int(ProjectileTypeId.SPLITTER_GUN)

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        base = 4.0
        if type_id == int(ProjectileTypeId.ASSAULT_RIFLE):
            base = 6.0
        elif type_id == int(ProjectileTypeId.SUBMACHINE_GUN):
            base = 8.0
        return max(2.0, base * scale)

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
        if self.bullet_trail_texture is None:
            return False
        if alpha <= 0:
            return False

        segment = end - start
        direction, dist = segment.normalized_with_length()

        # Native uses projectile travel direction as the side-offset basis and still emits the
        # trail quad even when origin≈head (degenerate impact frames).
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
        rl.rl_set_texture(self.bullet_trail_texture.id)
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

    def _draw_sharpshooter_laser_sight(
        self,
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
        if self.bullet_trail_texture is None:
            return

        players = self.players
        if not players:
            return

        tail_alpha = int(clamp(alpha * 0.5, 0.0, 1.0) * 255.0 + 0.5)
        head_alpha = int(clamp(alpha * 0.2, 0.0, 1.0) * 255.0 + 0.5)
        tail = rl.Color(255, 0, 0, tail_alpha)
        head = rl.Color(255, 0, 0, head_alpha)

        rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
        rl.rl_set_texture(self.bullet_trail_texture.id)
        rl.rl_begin(rd.RL_QUADS)

        for player in players:
            if float(getattr(player, "health", 0.0)) <= 0.0:
                continue
            if not perk_active(player, PerkId.SHARPSHOOTER):
                continue
            player_pos = getattr(player, "pos", None)
            if not isinstance(player_pos, Vec2):
                continue

            aim_heading = float(getattr(player, "aim_heading", 0.0))
            aim_dir = Vec2.from_heading(aim_heading)
            start = player_pos + aim_dir * 15.0
            end = player_pos + aim_dir * 512.0

            start_screen = self._world_to_screen_with(start, camera=camera, view_scale=view_scale)
            end_screen = self._world_to_screen_with(end, camera=camera, view_scale=view_scale)
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

    def _draw_secondary_projectile(self, proj: SecondaryProjectile, *, scale: float, alpha: float = 1.0) -> None:
        alpha = clamp(float(alpha), 0.0, 1.0)
        if alpha <= 1e-3:
            return
        proj_pos = proj.pos
        screen = self.world_to_screen(proj_pos)
        proj_type = int(proj.type_id)
        angle = float(proj.angle)

        ctx = SecondaryProjectileDrawCtx(
            renderer=cast("WorldRenderer", self),
            proj=proj,
            proj_type=int(proj_type),
            screen_pos=screen,
            angle=float(angle),
            scale=float(scale),
            alpha=float(alpha),
        )
        if draw_secondary_projectile_from_registry(ctx):
            return
        rl.draw_circle(
            int(screen.x), int(screen.y), max(1.0, 4.0 * scale), rl.Color(200, 200, 220, int(200 * alpha + 0.5))
        )
