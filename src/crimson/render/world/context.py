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
    from .renderer import WorldRenderer


class WorldRenderCtx(msgspec.Struct):
    renderer: WorldRenderer
    frame: RenderFrame
    projection_camera: Vec2 | None = None
    projection_view_scale: Vec2 | None = None

    def _camera_screen_size(
        self,
        *,
        runtime_w: float | None = None,
        runtime_h: float | None = None,
    ) -> Vec2:
        out_w = runtime_w if runtime_w is not None else float(rl.get_screen_width())
        out_h = runtime_h if runtime_h is not None else float(rl.get_screen_height())
        return viewport.camera_screen_size(
            world_size=self.frame.world_size,
            config=self.frame.config,
            runtime_w=out_w,
            runtime_h=out_h,
        )

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        return viewport.clamp_camera(
            world_size=self.frame.world_size,
            camera=camera,
            screen_size=screen_size,
        )

    def _world_params(self) -> tuple[Vec2, Vec2]:
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        camera, view_scale, _screen_size = viewport.view_transform(
            world_size=self.frame.world_size,
            config=self.frame.config,
            camera=self.frame.camera,
            out_size=out_size,
        )
        return camera, view_scale

    @staticmethod
    def _world_to_screen_with(pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
        return viewport.world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    @staticmethod
    def _view_scale_avg(view_scale: Vec2) -> float:
        return viewport.view_scale_avg(view_scale)

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

    def with_projection(self, *, camera: Vec2, view_scale: Vec2) -> WorldRenderCtx:
        return WorldRenderCtx(
            renderer=self.renderer,
            frame=self.frame,
            projection_camera=camera,
            projection_view_scale=view_scale,
        )

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return _is_bullet_trail_type(type_id)

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        return _bullet_sprite_size(type_id, scale=scale)

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
        return _draw_bullet_trail(
            self,
            start,
            end,
            type_id=type_id,
            alpha=alpha,
            scale=scale,
            angle=angle,
        )

    def world_to_screen(self, pos: Vec2) -> Vec2:
        camera = self.projection_camera
        view_scale = self.projection_view_scale
        if camera is None or view_scale is None:
            camera, view_scale = self._world_params()
        return self._world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        camera = self.projection_camera
        view_scale = self.projection_view_scale
        if camera is None or view_scale is None:
            camera, view_scale = self._world_params()
        return viewport.screen_to_world_with(pos, camera=camera, view_scale=view_scale)


def build_world_render_ctx(
    renderer: WorldRenderer,
    *,
    render_frame: RenderFrame,
) -> WorldRenderCtx:
    return WorldRenderCtx(
        renderer=renderer,
        frame=render_frame,
    )


def _is_bullet_trail_type(type_id: int) -> bool:
    return 0 <= type_id < 8 or type_id == ProjectileTemplateId.SPLITTER_GUN


def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
    base = 4.0
    if type_id == ProjectileTemplateId.ASSAULT_RIFLE:
        base = 6.0
    elif type_id == ProjectileTemplateId.SUBMACHINE_GUN:
        base = 8.0
    return max(2.0, base * scale)


def _draw_bullet_trail(
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
