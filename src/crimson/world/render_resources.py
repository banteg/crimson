from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import msgspec

from grim.assets import RuntimeResources, TextureId, runtime_resources_for
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ..creatures.anim import creature_corpse_frame_for_type
from ..creatures.runtime import CreaturePool
from ..render.frame import RenderFrame
from ..render.rtx.mode import RtxRenderMode
from ..render.terrain_fx import FxQueueTextures, bake_terrain_fx_batch
from ..sim.state_types import PlayerState
from ..sim.terrain_fx import TerrainFxBatch

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



class RenderResources(msgspec.Struct):
    assets_dir: Path
    world_size: float = 1024.0
    config: CrimsonConfig | None = None

    ground: GroundRenderer | None = None
    fx_textures: FxQueueTextures | None = None
    _pending_terrain_fx_batches: list[TerrainFxBatch] = msgspec.field(default_factory=list)
    _resources: RuntimeResources | None = None

    @property
    def resources(self) -> RuntimeResources:
        resources = self._resources
        assert resources is not None, "runtime resources must be loaded before use"
        return resources

    @resources.setter
    def resources(self, value: RuntimeResources | None) -> None:
        self._resources = value

    def registry_texture(self, texture_id: TextureId) -> rl.Texture:
        resources = self._resources
        if resources is not None:
            return resources.texture(texture_id)
        return runtime_resources_for(self.assets_dir).texture(texture_id)

    def sync_ground_settings(self) -> None:
        if self.ground is None:
            return
        if self.config is None:
            self.ground.texture_scale = 1.0
            return
        self.ground.texture_scale = self.config.display.texture_scale

    def set_ground_textures(
        self,
        *,
        base: rl.Texture,
        overlay: rl.Texture,
        detail: rl.Texture,
    ) -> None:
        self.clear_pending_terrain_fx()
        if self.ground is None:
            self.ground = GroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=int(self.world_size),
                height=int(self.world_size),
                texture_scale=1.0,
            )
        else:
            self.ground.texture = base
            self.ground.overlay = overlay
            self.ground.overlay_detail = detail
        self.sync_ground_settings()

    def schedule_ground_generation(self, *, seed: int) -> None:
        if self.ground is None:
            return
        self.ground.schedule_generate(seed=seed)

    def process_ground_pending(self) -> None:
        if self.ground is None:
            return
        self.ground.process_pending()
        if self.ground.texture_failed:
            self.clear_pending_terrain_fx()
            return
        if not self.ground.render_target_ready():
            return
        if self.fx_textures is None or not self._pending_terrain_fx_batches:
            return
        pending = tuple(self._pending_terrain_fx_batches)
        self._pending_terrain_fx_batches.clear()
        for batch in pending:
            self._bake_terrain_fx_batch(
                batch,
                corpse_frame_for_type=creature_corpse_frame_for_type,
            )

    def open(self, *, terrain_seed: int) -> None:
        self.close()
        resources = runtime_resources_for(self.assets_dir)
        self._resources = resources

        base = resources.texture(TextureId.TER_Q1_BASE)
        overlay = resources.texture(TextureId.TER_Q1_OVERLAY)
        self.set_ground_textures(base=base, overlay=overlay, detail=base)
        self.schedule_ground_generation(seed=terrain_seed)
        self.fx_textures = FxQueueTextures(
            particles=resources.texture(TextureId.PARTICLES),
            bodyset=resources.texture(TextureId.BODYSET),
        )

    def close(self) -> None:
        if self.ground is not None and self.ground.render_target is not None:
            rl.unload_render_texture(self.ground.render_target)
            self.ground.render_target = None
        self.ground = None

        self._resources = None
        self.fx_textures = None
        self.clear_pending_terrain_fx()

    def clear_pending_terrain_fx(self) -> None:
        self._pending_terrain_fx_batches.clear()

    def _bake_terrain_fx_batch(
        self,
        batch: TerrainFxBatch,
        *,
        corpse_frame_for_type: Callable[[int], int] = creature_corpse_frame_for_type,
    ) -> None:
        if self.ground is None or self.fx_textures is None:
            return
        if batch.is_empty():
            return
        bake_terrain_fx_batch(
            self.ground,
            batch=batch,
            textures=self.fx_textures,
            corpse_frame_for_type=corpse_frame_for_type,
        )

    def consume_terrain_fx_batch(
        self,
        batch: TerrainFxBatch,
        *,
        corpse_frame_for_type: Callable[[int], int] = creature_corpse_frame_for_type,
    ) -> None:
        if batch.is_empty():
            return
        ground = self.ground
        if ground is None or ground.texture_failed or self.fx_textures is None:
            return
        if ground.render_target_ready():
            self._bake_terrain_fx_batch(
                batch,
                corpse_frame_for_type=corpse_frame_for_type,
            )
            return
        self._pending_terrain_fx_batches.append(batch)

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
            resources=self.resources,
            elapsed_ms=float(elapsed_ms),
            bonus_anim_phase=float(bonus_anim_phase),
            rtx_mode=rtx_mode,
        )
