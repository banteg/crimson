from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import msgspec

from grim.assets import TextureId, runtime_resources_for
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ..creatures.anim import creature_corpse_frame_for_type
from ..creatures.runtime import CreaturePool
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import GameplayState
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.terrain_fx import FxQueueTextures, bake_fx_queues
from ..render.world_assets import WorldRenderAssets, build_world_render_assets
from ..sim.state_types import PlayerState


class RenderResources(msgspec.Struct):
    assets_dir: Path
    world_size: float = 1024.0
    config: CrimsonConfig | None = None

    ground: GroundRenderer | None = None
    fx_queue: FxQueue = msgspec.field(default_factory=FxQueue)
    fx_queue_rotated: FxQueueRotated = msgspec.field(default_factory=FxQueueRotated)
    fx_textures: FxQueueTextures | None = None
    assets: WorldRenderAssets | None = None

    def texture(self, texture_id: TextureId) -> rl.Texture:
        return runtime_resources_for(self.assets_dir).texture(texture_id)

    def sync_ground_settings(self) -> None:
        if self.ground is None:
            return
        if self.config is None:
            self.ground.texture_scale = 1.0
            self.ground.screen_width = None
            self.ground.screen_height = None
            return
        self.ground.texture_scale = self.config.texture_scale
        self.ground.screen_width = float(self.config.screen_width)
        self.ground.screen_height = float(self.config.screen_height)

    def set_ground_textures(
        self,
        *,
        base: rl.Texture,
        overlay: rl.Texture,
        detail: rl.Texture,
    ) -> None:
        if self.ground is None:
            self.ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(self.world_size),
                height=int(self.world_size),
                texture_scale=1.0,
                screen_width=None,
                screen_height=None,
            )
        else:
            self.ground.texture = base
            self.ground.overlay = overlay
            self.ground.overlay_detail = detail
        self.sync_ground_settings()

    def schedule_ground_generation(self, *, seed: int, layers: int = 3) -> None:
        if self.ground is None:
            return
        self.ground.schedule_generate(seed=int(seed), layers=int(layers))

    def process_ground_pending(self) -> None:
        if self.ground is None:
            return
        self.sync_ground_settings()
        self.ground.process_pending()

    def open(self, *, terrain_seed: int) -> None:
        self.close()
        self.assets = build_world_render_assets(runtime_resources_for(self.assets_dir))

        base = self.texture(TextureId.TER_Q1_BASE)
        overlay = self.texture(TextureId.TER_Q1_OVERLAY)
        self.set_ground_textures(base=base, overlay=overlay, detail=overlay)
        self.schedule_ground_generation(seed=int(terrain_seed), layers=3)
        assets = self.assets
        assert assets is not None
        self.fx_textures = FxQueueTextures(
            particles=assets.particles,
            bodyset=assets.bodyset,
        )

    def close(self) -> None:
        if self.ground is not None and self.ground.render_target is not None:
            rl.unload_render_texture(self.ground.render_target)
            self.ground.render_target = None
        self.ground = None

        self.assets = None
        self.fx_textures = None
        self.fx_queue.clear()
        self.fx_queue_rotated.clear()

    def bake_fx_queues(
        self,
        *,
        corpse_frame_for_type: Callable[[int], int] = creature_corpse_frame_for_type,
    ) -> None:
        if self.ground is None or self.fx_textures is None:
            return
        if not (self.fx_queue.count or self.fx_queue_rotated.count):
            return
        bake_fx_queues(
            self.ground,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            textures=self.fx_textures,
            corpse_frame_for_type=corpse_frame_for_type,
        )

    def build_render_frame(
        self,
        *,
        state: GameplayState,
        players: list[PlayerState],
        creatures: CreaturePool,
        camera: Vec2,
        demo_mode_active: bool,
        elapsed_ms: float,
        bonus_anim_phase: float,
        lan_player_rings_enabled: bool,
        lan_local_aim_indicators_only: bool,
        lan_local_player_slot_index: int,
        rtx_mode: RtxRenderMode,
    ) -> RenderFrame:
        return RenderFrame(
            world_size=float(self.world_size),
            demo_mode_active=bool(demo_mode_active),
            config=self.config,
            camera=camera,
            ground=self.ground,
            state=state,
            players=players,
            creatures=creatures,
            assets=self.assets,
            elapsed_ms=float(elapsed_ms),
            bonus_anim_phase=float(bonus_anim_phase),
            lan_player_rings_enabled=bool(lan_player_rings_enabled),
            lan_local_aim_indicators_only=bool(lan_local_aim_indicators_only),
            lan_local_player_slot_index=int(lan_local_player_slot_index),
            rtx_mode=rtx_mode,
        )
