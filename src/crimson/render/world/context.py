from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.raylib_api import rl

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
    frame: RenderFrame | None = None

    @property
    def assets_dir(self) -> Path:
        if self.frame is not None:
            return self.frame.assets_dir
        return self.renderer._world.assets_dir

    @property
    def world_size(self) -> float:
        if self.frame is not None:
            return self.frame.world_size
        return self.renderer._world.world_size

    @property
    def demo_mode_active(self) -> bool:
        if self.frame is not None:
            return self.frame.demo_mode_active
        return self.renderer._world.demo_mode_active

    @property
    def config(self) -> CrimsonConfig | None:
        if self.frame is not None:
            return self.frame.config
        return self.renderer._world.config

    @property
    def camera(self) -> Vec2:
        if self.frame is not None:
            return self.frame.camera
        return self.renderer._world.camera

    @property
    def ground(self) -> GroundRenderer | None:
        if self.frame is not None:
            return self.frame.ground
        return self.renderer._world.ground

    @property
    def state(self) -> GameplayState:
        if self.frame is not None:
            return self.frame.state
        return self.renderer._world.state

    @property
    def players(self) -> list[PlayerState]:
        if self.frame is not None:
            return self.frame.players
        return self.renderer._world.players

    @property
    def creatures(self) -> CreaturePool:
        if self.frame is not None:
            return self.frame.creatures
        return self.renderer._world.creatures

    @property
    def creature_textures(self) -> dict[str, rl.Texture]:
        if self.frame is not None:
            return self.frame.creature_textures
        return self.renderer._world.creature_textures

    @property
    def projs_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.projs_texture
        return self.renderer._world.projs_texture

    @property
    def particles_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.particles_texture
        return self.renderer._world.particles_texture

    @property
    def bullet_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.bullet_texture
        return self.renderer._world.bullet_texture

    @property
    def bullet_trail_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.bullet_trail_texture
        return self.renderer._world.bullet_trail_texture

    @property
    def arrow_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.arrow_texture
        return self.renderer._world.arrow_texture

    @property
    def bonuses_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.bonuses_texture
        return self.renderer._world.bonuses_texture

    @property
    def bodyset_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.bodyset_texture
        return self.renderer._world.bodyset_texture

    @property
    def clock_table_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.clock_table_texture
        return self.renderer._world.clock_table_texture

    @property
    def clock_pointer_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.clock_pointer_texture
        return self.renderer._world.clock_pointer_texture

    @property
    def aim_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.aim_texture
        return self.renderer._world.aim_texture

    @property
    def muzzle_flash_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.muzzle_flash_texture
        return self.renderer._world.muzzle_flash_texture

    @property
    def wicons_texture(self) -> rl.Texture | None:
        if self.frame is not None:
            return self.frame.wicons_texture
        return self.renderer._world.wicons_texture

    @property
    def elapsed_ms(self) -> float:
        if self.frame is not None:
            return self.frame.elapsed_ms
        return float(self.renderer._world.sim_world.elapsed_ms)

    @property
    def bonus_anim_phase(self) -> float:
        if self.frame is not None:
            return self.frame.bonus_anim_phase
        return float(self.renderer._world.sim_world.bonus_anim_phase)

    @property
    def lan_player_rings_enabled(self) -> bool:
        if self.frame is not None:
            return bool(self.frame.lan_player_rings_enabled)
        return bool(self.renderer._world.lan_player_rings_enabled)

    @property
    def lan_local_aim_indicators_only(self) -> bool:
        if self.frame is not None:
            return bool(self.frame.lan_local_aim_indicators_only)
        return bool(self.renderer._world.lan_local_aim_indicators_only)

    @property
    def lan_local_player_slot_index(self) -> int:
        if self.frame is not None:
            return int(self.frame.lan_local_player_slot_index)
        return int(self.renderer._world.lan_local_player_slot_index)

    @property
    def rtx_mode(self) -> RtxRenderMode:
        if self.frame is not None:
            return self.frame.rtx_mode
        return self.renderer._world.rtx_mode

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

    def world_to_screen(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return self._world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
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
    return WorldRenderCtx(renderer=renderer, frame=render_frame)
