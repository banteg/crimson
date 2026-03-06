from __future__ import annotations

import msgspec

from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl

from ..frame import RenderFrame
from . import viewport
from .context import build_world_render_ctx
from .draw import draw_world


class WorldRenderer(msgspec.Struct):
    world_size: float
    config: CrimsonConfig | None
    camera: Vec2

    def sync_viewport(
        self,
        *,
        world_size: float,
        config: CrimsonConfig | None,
        camera: Vec2,
    ) -> None:
        self.world_size = float(world_size)
        self.config = config
        self.camera = camera

    def draw(
        self,
        *,
        render_frame: RenderFrame,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        self.sync_viewport(
            world_size=render_frame.world_size,
            config=render_frame.config,
            camera=render_frame.camera,
        )
        render_ctx = build_world_render_ctx(self, render_frame=render_frame)
        draw_world(
            render_ctx,
            draw_aim_indicators=draw_aim_indicators,
            entity_alpha=entity_alpha,
        )

    def _camera_screen_size(
        self,
        *,
        runtime_w: float | None = None,
        runtime_h: float | None = None,
    ) -> Vec2:
        out_w = runtime_w if runtime_w is not None else float(rl.get_screen_width())
        out_h = runtime_h if runtime_h is not None else float(rl.get_screen_height())
        return viewport.camera_screen_size(
            world_size=self.world_size,
            config=self.config,
            runtime_w=out_w,
            runtime_h=out_h,
        )

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        return viewport.clamp_camera(
            world_size=self.world_size,
            camera=camera,
            screen_size=screen_size,
        )

    def _world_params(self) -> tuple[Vec2, Vec2]:
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        camera, view_scale, _screen_size = viewport.view_transform(
            world_size=self.world_size,
            config=self.config,
            camera=self.camera,
            out_size=out_size,
        )
        return camera, view_scale

    def world_to_screen(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return viewport.world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return viewport.screen_to_world_with(pos, camera=camera, view_scale=view_scale)
