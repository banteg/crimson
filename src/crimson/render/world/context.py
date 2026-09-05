from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.assets import TextureId
from grim.geom import Vec2
from grim.raylib_api import rd, rl

from ...projectiles.types import ProjectileTemplateId
from . import viewport
from .constants import _RAD_TO_DEG

if TYPE_CHECKING:
    from ..frame import RenderFrame


class WorldRenderCtx(msgspec.Struct, frozen=True):
    frame: RenderFrame
    view: viewport.ViewTransform

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
        grid = max(1, int(grid))
        frame = max(0, int(frame))
        cell_w = float(texture.width) / float(grid)
        cell_h = float(texture.height) / float(grid)
        col = frame % grid
        row = frame // grid
        src = rl.Rectangle(cell_w * float(col), cell_h * float(row), cell_w, cell_h)
        w = cell_w * float(scale)
        h = cell_h * float(scale)
        dst = rl.Rectangle(pos.x, pos.y, w, h)
        origin = rl.Vector2(w * 0.5, h * 0.5)
        rl.draw_texture_pro(texture, src, dst, origin, float(rotation_rad * _RAD_TO_DEG), tint)

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self.view.world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self.view.screen_to_world(pos)


def is_bullet_trail_type(type_id: int) -> bool:
    return 0 <= type_id < 8 or type_id == ProjectileTemplateId.SPLITTER_GUN


def bullet_sprite_size(type_id: int, *, scale: float) -> float:
    base = 4.0
    if type_id == ProjectileTemplateId.ASSAULT_RIFLE:
        base = 6.0
    elif type_id == ProjectileTemplateId.SUBMACHINE_GUN:
        base = 8.0
    return max(2.0, base * scale)


def draw_bullet_trail_quad(
    render_ctx: WorldRenderCtx,
    start: Vec2,
    end: Vec2,
    *,
    type_id: int,
    alpha: int,
    scale: float,
    angle: float,
) -> bool:
    bullet_trail_texture = render_ctx.frame.resources.texture(TextureId.BULLET_TRAIL)
    if alpha <= 0:
        return False

    segment = end - start
    direction, dist = segment.normalized_with_length()

    # Native uses projectile travel direction as the side-offset basis and still emits the
    # trail quad even when origin=head (degenerate impact frames).
    if type_id in (ProjectileTemplateId.PISTOL, ProjectileTemplateId.ASSAULT_RIFLE):
        side_mul = 1.2
    elif type_id == ProjectileTemplateId.GAUSS_GUN:
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
    if type_id == ProjectileTemplateId.GAUSS_GUN:
        head_rgb = (51, 128, 255)  # (0.2, 0.5, 1.0)
    else:
        head_rgb = (128, 128, 128)  # (0.5, 0.5, 0.5)

    tail_rgb = (128, 128, 128)
    head = rl.Color(head_rgb[0], head_rgb[1], head_rgb[2], alpha)
    tail = rl.Color(tail_rgb[0], tail_rgb[1], tail_rgb[2], 0)

    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
    rl.rl_set_texture(bullet_trail_texture.id)
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
