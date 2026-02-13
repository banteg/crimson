from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.geom import Vec2
from grim.fonts.small import SmallFontData, load_small_font_optional

from .constants import _RAD_TO_DEG
from .mixin_base import WorldRendererMixinBase

if TYPE_CHECKING:
    from pathlib import Path

    from grim.config import CrimsonConfig
    from grim.terrain_render import GroundRenderer

    from ...creatures.runtime import CreaturePool
    from ...gameplay import GameplayState
    from ...sim.state_types import PlayerState


class WorldRendererContextMixin(WorldRendererMixinBase):
    @property
    def assets_dir(self) -> Path:
        frame = self._render_frame
        if frame is not None:
            return frame.assets_dir
        return self._world.assets_dir

    @property
    def missing_assets(self) -> list[str]:
        frame = self._render_frame
        if frame is not None:
            return frame.missing_assets
        return self._world.missing_assets

    @property
    def world_size(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.world_size
        return self._world.world_size

    @property
    def demo_mode_active(self) -> bool:
        frame = self._render_frame
        if frame is not None:
            return frame.demo_mode_active
        return self._world.demo_mode_active

    @property
    def config(self) -> CrimsonConfig | None:
        frame = self._render_frame
        if frame is not None:
            return frame.config
        return self._world.config

    @property
    def camera(self) -> Vec2:
        frame = self._render_frame
        if frame is not None:
            return frame.camera
        return self._world.camera

    @property
    def ground(self) -> GroundRenderer | None:
        frame = self._render_frame
        if frame is not None:
            return frame.ground
        return self._world.ground

    @property
    def state(self) -> GameplayState:
        frame = self._render_frame
        if frame is not None:
            return frame.state
        return self._world.state

    @property
    def players(self) -> list[PlayerState]:
        frame = self._render_frame
        if frame is not None:
            return frame.players
        return self._world.players

    @property
    def creatures(self) -> CreaturePool:
        frame = self._render_frame
        if frame is not None:
            return frame.creatures
        return self._world.creatures

    @property
    def creature_textures(self) -> dict[str, rl.Texture]:
        frame = self._render_frame
        if frame is not None:
            return frame.creature_textures
        return self._world.creature_textures

    @property
    def projs_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.projs_texture
        return self._world.projs_texture

    @property
    def particles_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.particles_texture
        return self._world.particles_texture

    @property
    def bullet_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bullet_texture
        return self._world.bullet_texture

    @property
    def bullet_trail_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bullet_trail_texture
        return self._world.bullet_trail_texture

    @property
    def arrow_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.arrow_texture
        return self._world.arrow_texture

    @property
    def bonuses_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bonuses_texture
        return self._world.bonuses_texture

    @property
    def bodyset_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.bodyset_texture
        return self._world.bodyset_texture

    @property
    def clock_table_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.clock_table_texture
        return self._world.clock_table_texture

    @property
    def clock_pointer_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.clock_pointer_texture
        return self._world.clock_pointer_texture

    @property
    def muzzle_flash_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.muzzle_flash_texture
        return self._world.muzzle_flash_texture

    @property
    def wicons_texture(self) -> rl.Texture | None:
        frame = self._render_frame
        if frame is not None:
            return frame.wicons_texture
        return self._world.wicons_texture

    @property
    def elapsed_ms(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.elapsed_ms
        return float(self._world._elapsed_ms)

    @property
    def bonus_anim_phase(self) -> float:
        frame = self._render_frame
        if frame is not None:
            return frame.bonus_anim_phase
        return float(self._world._bonus_anim_phase)

    def _ensure_small_font(self) -> SmallFontData | None:
        if self._small_font is not None:
            return self._small_font
        # Keep UI text consistent with the HUD/menu font when available.
        self._small_font = load_small_font_optional(self.assets_dir, self.missing_assets)
        return self._small_font

    def _camera_screen_size(self) -> Vec2:
        if self.config is not None:
            screen_w = float(self.config.screen_width)
            screen_h = float(self.config.screen_height)
        else:
            screen_w = float(rl.get_screen_width())
            screen_h = float(rl.get_screen_height())
        if screen_w > self.world_size:
            screen_w = float(self.world_size)
        if screen_h > self.world_size:
            screen_h = float(self.world_size)
        return Vec2(screen_w, screen_h)

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
        screen_size = self._camera_screen_size()
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
