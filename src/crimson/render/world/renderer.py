from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pyray as rl

from grim.fonts.small import SmallFontData
from grim.geom import Vec2

from ..frame import RenderFrame
from .context import WorldRenderCtx, build_world_render_ctx
from .draw import (
    WorldDrawContext,
    draw_world,
)
from .draw import (
    draw_aim_enhancements as draw_aim_enhancements_pass,
)
from .draw import (
    draw_aim_indicators as draw_aim_indicators_pass,
)
from .overlays import draw_aim_circle as draw_aim_circle_overlay
from .overlays import draw_clock_gauge as draw_clock_gauge_overlay
from .projectiles import (
    bullet_sprite_size,
    draw_bullet_trail,
    draw_projectile,
    draw_secondary_projectile,
    is_bullet_trail_type,
)
from .trooper import draw_player_trooper_sprite

if TYPE_CHECKING:
    from ...game_world import GameWorld
    from ...projectiles import Projectile, SecondaryProjectile
    from ...sim.state_types import PlayerState


@dataclass
class WorldRenderer:
    _world: GameWorld
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

    @property
    def config(self):
        return self._active_render_ctx().config

    @property
    def players(self):
        return self._active_render_ctx().players

    @property
    def creatures(self):
        return self._active_render_ctx().creatures

    @property
    def projs_texture(self):
        return self._active_render_ctx().projs_texture

    @property
    def particles_texture(self):
        return self._active_render_ctx().particles_texture

    @property
    def bullet_texture(self):
        return self._active_render_ctx().bullet_texture

    @property
    def bullet_trail_texture(self):
        return self._active_render_ctx().bullet_trail_texture

    @property
    def elapsed_ms(self) -> float:
        return self._active_render_ctx().elapsed_ms

    def world_to_screen(self, pos: Vec2) -> Vec2:
        return self._active_render_ctx().world_to_screen(pos)

    def screen_to_world(self, pos: Vec2) -> Vec2:
        return self._active_render_ctx().screen_to_world(pos)

    def _world_to_screen_with(self, pos: Vec2, *, camera: Vec2, view_scale: Vec2) -> Vec2:
        return self._active_render_ctx()._world_to_screen_with(pos, camera=camera, view_scale=view_scale)

    def _view_scale_avg(self, view_scale: Vec2) -> float:
        return self._active_render_ctx()._view_scale_avg(view_scale)

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
        self._active_render_ctx()._draw_atlas_sprite(
            texture,
            grid=grid,
            frame=frame,
            pos=pos,
            scale=scale,
            rotation_rad=rotation_rad,
            tint=tint,
        )

    @staticmethod
    def _is_bullet_trail_type(type_id: int) -> bool:
        return is_bullet_trail_type(type_id)

    @staticmethod
    def _bullet_sprite_size(type_id: int, *, scale: float) -> float:
        return bullet_sprite_size(type_id, scale=scale)

    def _draw_aim_circle(self, *, center: Vec2, radius: float, alpha: float = 1.0) -> None:
        draw_aim_circle_overlay(self._active_render_ctx(), center=center, radius=radius, alpha=alpha)

    def _draw_clock_gauge(self, *, pos: Vec2, ms: int, scale: float, alpha: float = 1.0) -> None:
        draw_clock_gauge_overlay(self._active_render_ctx(), pos=pos, ms=ms, scale=scale, alpha=alpha)

    def _draw_aim_indicators(self, *, ctx: WorldDrawContext) -> None:
        draw_aim_indicators_pass(
            self._active_render_ctx(),
            ctx=ctx,
            world_to_screen_with=lambda pos, camera, view_scale: self._world_to_screen_with(
                pos,
                camera=camera,
                view_scale=view_scale,
            ),
            draw_aim_circle_fn=lambda center, radius, alpha: self._draw_aim_circle(
                center=center,
                radius=radius,
                alpha=alpha,
            ),
            draw_clock_gauge_fn=lambda pos, ms, scale, alpha: self._draw_clock_gauge(
                pos=pos,
                ms=ms,
                scale=scale,
                alpha=alpha,
            ),
        )

    def _draw_aim_enhancements(self, *, ctx: WorldDrawContext) -> None:
        draw_aim_enhancements_pass(
            self._active_render_ctx(),
            ctx=ctx,
            world_to_screen_with=lambda pos, camera, view_scale: self._world_to_screen_with(
                pos,
                camera=camera,
                view_scale=view_scale,
            ),
        )

    def _draw_projectile(self, proj: Projectile, *, proj_index: int = 0, scale: float, alpha: float = 1.0) -> None:
        draw_projectile(
            self._active_render_ctx(),
            proj,
            proj_index=proj_index,
            scale=scale,
            alpha=alpha,
        )

    def _draw_secondary_projectile(self, proj: SecondaryProjectile, *, scale: float, alpha: float = 1.0) -> None:
        draw_secondary_projectile(
            self._active_render_ctx(),
            proj,
            scale=scale,
            alpha=alpha,
        )

    def _draw_player_trooper_sprite(
        self,
        texture: rl.Texture,
        player: PlayerState,
        *,
        camera: Vec2,
        view_scale: Vec2,
        scale: float,
        alpha: float = 1.0,
    ) -> None:
        draw_player_trooper_sprite(
            self._active_render_ctx(),
            texture,
            player,
            camera=camera,
            view_scale=view_scale,
            scale=scale,
            alpha=alpha,
        )

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
            self._active_render_ctx(),
            start,
            end,
            type_id=type_id,
            alpha=alpha,
            scale=scale,
            angle=angle,
        )
