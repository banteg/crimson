from __future__ import annotations

from collections.abc import Callable

import msgspec

from grim.geom import Vec2
from grim.raylib_api import rl

from ..frame import RenderFrame
from . import viewport
from .context import build_world_render_ctx
from .draw import draw_world


class WorldRenderer(msgspec.Struct):
    _build_render_frame: Callable[[], RenderFrame]
    _build_viewport_state: Callable[[], viewport.WorldViewportState]
    _render_frame: RenderFrame | None = None
    _viewport_state: viewport.WorldViewportState | None = None

    def _active_render_frame(self) -> RenderFrame:
        if self._render_frame is not None:
            return self._render_frame
        return self._build_render_frame()

    def _active_viewport_state(self) -> viewport.WorldViewportState:
        if self._viewport_state is not None:
            return self._viewport_state
        return self._build_viewport_state()

    @staticmethod
    def _viewport_state_from_frame(frame: RenderFrame) -> viewport.WorldViewportState:
        return viewport.WorldViewportState(
            world_size=frame.world_size,
            config=frame.config,
            camera=frame.camera,
        )

    def draw(
        self,
        *,
        render_frame: RenderFrame | None = None,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        frame = render_frame if render_frame is not None else self._build_render_frame()
        self._render_frame = frame
        self._viewport_state = self._viewport_state_from_frame(frame)
        try:
            render_ctx = build_world_render_ctx(self, render_frame=frame)
            draw_world(
                render_ctx,
                draw_aim_indicators=draw_aim_indicators,
                entity_alpha=entity_alpha,
            )
        finally:
            self._render_frame = None
            self._viewport_state = None

    def _camera_screen_size(
        self,
        *,
        runtime_w: float | None = None,
        runtime_h: float | None = None,
    ) -> Vec2:
        viewport_state = self._active_viewport_state()
        out_w = runtime_w if runtime_w is not None else float(rl.get_screen_width())
        out_h = runtime_h if runtime_h is not None else float(rl.get_screen_height())
        return viewport.camera_screen_size(
            world_size=viewport_state.world_size,
            config=viewport_state.config,
            runtime_w=out_w,
            runtime_h=out_h,
        )

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        viewport_state = self._active_viewport_state()
        return viewport.clamp_camera(
            world_size=viewport_state.world_size,
            camera=camera,
            screen_size=screen_size,
        )

    def _world_params(self) -> tuple[Vec2, Vec2]:
        viewport_state = self._active_viewport_state()
        out_size = Vec2(float(rl.get_screen_width()), float(rl.get_screen_height()))
        camera, view_scale, _screen_size = viewport.view_transform(
            world_size=viewport_state.world_size,
            config=viewport_state.config,
            camera=viewport_state.camera,
            out_size=out_size,
        )
        return camera, view_scale

    def world_to_screen(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return viewport.world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        camera, view_scale = self._world_params()
        return viewport.screen_to_world_with(pos, camera=camera, view_scale=view_scale)
