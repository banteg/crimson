from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.raylib_api import rd, rl

from ...projectiles.types import ProjectileTemplateId
from ..rtx.mode import RtxRenderMode
from .constants import _RAD_TO_DEG

if TYPE_CHECKING:
    from pathlib import Path

    from grim.config import CrimsonConfig
    from grim.terrain_render import GroundRenderer

    from ...creatures.runtime import CreaturePool
    from ...gameplay import GameplayState
    from ...sim.state_types import PlayerState
    from ..frame import RenderFrame
    from .renderer import WorldRenderer


class WorldRenderCtx(msgspec.Struct):
    renderer: WorldRenderer
    frame: RenderFrame
    projection_camera: Vec2 | None = None
    projection_view_scale: Vec2 | None = None

    @property
    def assets_dir(self) -> Path:
        return self.frame.assets_dir

    @property
    def world_size(self) -> float:
        return self.frame.world_size

    @property
    def demo_mode_active(self) -> bool:
        return self.frame.demo_mode_active

    @property
    def config(self) -> CrimsonConfig | None:
        return self.frame.config

    @property
    def camera(self) -> Vec2:
        return self.frame.camera

    @property
    def ground(self) -> GroundRenderer | None:
        return self.frame.ground

    @property
    def state(self) -> GameplayState:
        return self.frame.state

    @property
    def players(self) -> list[PlayerState]:
        return self.frame.players

    @property
    def creatures(self) -> CreaturePool:
        return self.frame.creatures

    @property
    def creature_textures(self) -> dict[str, rl.Texture]:
        return self.frame.creature_textures

    @property
    def projs_texture(self) -> rl.Texture | None:
        return self.frame.projs_texture

    @property
    def particles_texture(self) -> rl.Texture | None:
        return self.frame.particles_texture

    @property
    def bullet_texture(self) -> rl.Texture | None:
        return self.frame.bullet_texture

    @property
    def bullet_trail_texture(self) -> rl.Texture | None:
        return self.frame.bullet_trail_texture

    @property
    def arrow_texture(self) -> rl.Texture | None:
        return self.frame.arrow_texture

    @property
    def bonuses_texture(self) -> rl.Texture | None:
        return self.frame.bonuses_texture

    @property
    def bodyset_texture(self) -> rl.Texture | None:
        return self.frame.bodyset_texture

    @property
    def clock_table_texture(self) -> rl.Texture | None:
        return self.frame.clock_table_texture

    @property
    def clock_pointer_texture(self) -> rl.Texture | None:
        return self.frame.clock_pointer_texture

    @property
    def aim_texture(self) -> rl.Texture | None:
        return self.frame.aim_texture

    @property
    def muzzle_flash_texture(self) -> rl.Texture | None:
        return self.frame.muzzle_flash_texture

    @property
    def wicons_texture(self) -> rl.Texture | None:
        return self.frame.wicons_texture

    @property
    def elapsed_ms(self) -> float:
        return self.frame.elapsed_ms

    @property
    def bonus_anim_phase(self) -> float:
        return self.frame.bonus_anim_phase

    @property
    def lan_player_rings_enabled(self) -> bool:
        return bool(self.frame.lan_player_rings_enabled)

    @property
    def lan_local_aim_indicators_only(self) -> bool:
        return bool(self.frame.lan_local_aim_indicators_only)

    @property
    def lan_local_player_slot_index(self) -> int:
        return int(self.frame.lan_local_player_slot_index)

    @property
    def rtx_mode(self) -> RtxRenderMode:
        return self.frame.rtx_mode

    def _ensure_small_font(self) -> SmallFontData | None:
        if self.renderer._small_font is not None:
            return self.renderer._small_font
        self.renderer._small_font = load_small_font(self.assets_dir)
        return self.renderer._small_font

    def _camera_screen_size(
        self,
        *,
        runtime_w: float | None = None,
        runtime_h: float | None = None,
    ) -> Vec2:
        if runtime_w is None:
            runtime_w = float(rl.get_screen_width())
        if runtime_h is None:
            runtime_h = float(rl.get_screen_height())
        if runtime_w > 0.0 and runtime_h > 0.0:
            # Prefer live framebuffer dimensions. Config values can lag behind
            # the actual game window resolution during launcher/state handoff.
            screen_w = runtime_w
            screen_h = runtime_h
        elif self.config is not None:
            screen_w = float(self.config.screen_width)
            screen_h = float(self.config.screen_height)
        else:
            screen_w = max(1.0, runtime_w)
            screen_h = max(1.0, runtime_h)
        world = float(self.world_size)
        if world <= 0.0:
            return Vec2(max(1.0, screen_w), max(1.0, screen_h))
        out_w = max(1.0, screen_w)
        out_h = max(1.0, screen_h)
        scale = max(out_w / world, out_h / world, 1.0)
        return Vec2(min(world, out_w / scale), min(world, out_h / scale))

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        cam_x = camera.x
        cam_y = camera.y
        if cam_x > -1.0:
            cam_x = -1.0
        if cam_y > -1.0:
            cam_y = -1.0
        min_x = screen_size.x - float(self.world_size)
        min_y = screen_size.y - float(self.world_size)
        if cam_x < min_x:
            cam_x = min_x
        if cam_y < min_y:
            cam_y = min_y
        return Vec2(cam_x, cam_y)

    def _world_params(self) -> tuple[Vec2, Vec2]:
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        screen_size = self._camera_screen_size(runtime_w=out_size.x, runtime_h=out_size.y)
        camera = self._clamp_camera(self.camera, screen_size)
        scale_x = out_size.x / screen_size.x if screen_size.x > 0 else 1.0
        scale_y = out_size.y / screen_size.y if screen_size.y > 0 else 1.0
        return camera, Vec2(scale_x, scale_y)

    @staticmethod
    def _world_to_screen_with(pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
        return (pos + camera).mul_components(view_scale)

    @staticmethod
    def _view_scale_avg(view_scale: Vec2) -> float:
        return view_scale.avg_component()

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
        safe_scale = Vec2(
            view_scale.x if view_scale.x > 0.0 else 1.0,
            view_scale.y if view_scale.y > 0.0 else 1.0,
        )
        return pos.div_components(safe_scale) - camera


def build_world_render_ctx(
    renderer: WorldRenderer,
    *,
    render_frame: RenderFrame | None = None,
) -> WorldRenderCtx:
    frame = render_frame if render_frame is not None else renderer._active_render_frame()
    return WorldRenderCtx(renderer=renderer, frame=frame)


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
    if render_ctx.bullet_trail_texture is None:
        return False
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
