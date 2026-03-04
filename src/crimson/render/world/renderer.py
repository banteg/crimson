from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

import msgspec

from grim.fonts.small import SmallFontData
from grim.geom import Vec2

from ..frame import RenderFrame
from .context import WorldRenderCtx, build_world_render_ctx
from .draw import draw_world

if TYPE_CHECKING:
    from pathlib import Path

    from grim.config import CrimsonConfig

    from ...world.render_resources import RenderResources
    from ...world.sim_world_state import SimWorldState
    from ..rtx.mode import RtxRenderMode


class WorldRenderHost(Protocol):
    assets_dir: Path
    world_size: float
    demo_mode_active: bool
    config: CrimsonConfig | None
    camera: Vec2
    render_resources: RenderResources
    sim_world: SimWorldState
    lan_player_rings_enabled: bool
    lan_local_aim_indicators_only: bool
    lan_local_player_slot_index: int
    rtx_mode: RtxRenderMode

    def build_render_frame(self) -> RenderFrame: ...


class WorldRenderer(msgspec.Struct):
    _world: WorldRenderHost
    _render_frame: RenderFrame | None = None
    _small_font: SmallFontData | None = None

    def _active_render_ctx(self) -> WorldRenderCtx:
        return build_world_render_ctx(self, render_frame=self._render_frame)

    def draw(
        self,
        *,
        render_frame: RenderFrame | None = None,
        draw_aim_indicators: bool = True,
        entity_alpha: float = 1.0,
    ) -> None:
        frame = render_frame if render_frame is not None else self._world.build_render_frame()
        self._render_frame = frame
        try:
            render_ctx = build_world_render_ctx(self, render_frame=frame)
            draw_world(
                render_ctx,
                draw_aim_indicators=draw_aim_indicators,
                entity_alpha=entity_alpha,
            )
        finally:
            self._render_frame = None

    def _camera_screen_size(
        self,
        *,
        runtime_w: float | None = None,
        runtime_h: float | None = None,
    ) -> Vec2:
        return self._active_render_ctx()._camera_screen_size(runtime_w=runtime_w, runtime_h=runtime_h)

    def _clamp_camera(self, camera: Vec2, screen_size: Vec2) -> Vec2:
        return self._active_render_ctx()._clamp_camera(camera, screen_size)

    def _world_params(self) -> tuple[Vec2, Vec2]:
        return self._active_render_ctx()._world_params()

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._active_render_ctx().world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._active_render_ctx().screen_to_world(pos)
