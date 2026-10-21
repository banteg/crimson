from __future__ import annotations

from pathlib import Path

import msgspec

from grim.assets import RuntimeResources, TextureId, runtime_resources_for
from grim.config import CrimsonConfig
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer
from grim.terrain_stamps import TerrainLayers

from ..creatures.anim import creature_corpse_frame_for_type
from ..render.rtx.bonus_lighting import BonusLighting
from ..render.rtx.creature_lighting import CreatureLighting
from ..render.rtx.hdr import HdrRenderer
from ..render.rtx.materials import MaterialGroundRenderer
from ..render.rtx.mode import RtxRenderMode
from ..render.rtx.player_lighting import PlayerLighting
from ..render.rtx.smoke import SmokeRenderer
from ..render.terrain_fx import FxQueueTextures, bake_terrain_fx_batch
from ..sim.smoke_events import SmokeEmission
from ..sim.state_types import TERRAIN_SIZE
from ..sim.terrain_fx import TerrainFxBatch


class RenderResources(msgspec.Struct):
    assets_dir: Path
    config: CrimsonConfig | None = None
    rtx_mode: RtxRenderMode = RtxRenderMode.CLASSIC
    simulated_smoke_enabled: bool = True
    smoke: SmokeRenderer = msgspec.field(default_factory=SmokeRenderer)

    ground: GroundRenderer | None = None
    fx_textures: FxQueueTextures | None = None
    hdr: HdrRenderer = msgspec.field(default_factory=HdrRenderer)
    creature_lighting: CreatureLighting = msgspec.field(default_factory=CreatureLighting)
    player_lighting: PlayerLighting = msgspec.field(default_factory=PlayerLighting)
    bonus_lighting: BonusLighting = msgspec.field(default_factory=BonusLighting)
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

    def set_ground_textures(
        self,
        *,
        base: rl.Texture,
        overlay: rl.Texture,
        detail: rl.Texture,
    ) -> None:
        self.clear_pending_terrain_fx()
        self.smoke.reset()
        if self.ground is None:
            self.ground = MaterialGroundRenderer(
                texture=base,
                overlay=overlay,
                overlay_detail=detail,
                width=TERRAIN_SIZE,
                height=TERRAIN_SIZE,
            )
        else:
            self.ground.texture = base
            self.ground.overlay = overlay
            self.ground.overlay_detail = detail

    @property
    def texture_scale(self) -> float:
        return 1.0 if self.config is None else self.config.display.texture_scale

    def schedule_ground_stamps(self, layers: TerrainLayers) -> None:
        if self.ground is None:
            return
        self.ground.schedule_stamps(layers, texture_scale=self.texture_scale)

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
            self.bake_terrain_fx_batch(batch, self.ground)

    def open(self) -> None:
        self.close()
        resources = runtime_resources_for(self.assets_dir)
        self._resources = resources

        base = resources.texture(TextureId.TER_Q1_BASE)
        overlay = resources.texture(TextureId.TER_Q1_OVERLAY)
        # The ground stays clear until a terrain setup is applied.
        self.set_ground_textures(base=base, overlay=overlay, detail=base)
        self.fx_textures = FxQueueTextures(
            particles=resources.texture(TextureId.PARTICLES),
            bodyset=resources.texture(TextureId.BODYSET),
        )

    def close(self) -> None:
        self.smoke.close()
        if self.ground is not None:
            self.ground.close()
        self.ground = None
        self.hdr.close()
        self.creature_lighting.close()
        self.player_lighting.close()
        self.bonus_lighting.close()

        self._resources = None
        self.fx_textures = None
        self.clear_pending_terrain_fx()

    def clear_pending_terrain_fx(self) -> None:
        self._pending_terrain_fx_batches.clear()

    def set_simulated_smoke(self, enabled: bool) -> None:
        self.simulated_smoke_enabled = enabled
        self.sync_smoke_mode()

    def sync_smoke_mode(self) -> bool:
        enabled = self.simulated_smoke_enabled and self.rtx_mode is RtxRenderMode.RTX and (
            self.config is None or self.config.display.smoke_enabled
        )
        if not enabled:
            self.smoke.reset()
        return enabled

    def consume_smoke_batch(self, emissions: tuple[SmokeEmission, ...], *, dt_sim: float) -> None:
        if self.sync_smoke_mode():
            self.smoke.consume(emissions, dt_sim=dt_sim)

    def bake_terrain_fx_batch(self, batch: TerrainFxBatch, ground: GroundRenderer) -> None:
        """Bakes a tick's decals and corpses into `ground`: the run's, or another copy of its terrain."""
        if self.fx_textures is None or batch.is_empty():
            return
        if isinstance(ground, MaterialGroundRenderer):
            ground.material_batches.append(batch)
        bake_terrain_fx_batch(
            ground,
            batch=batch,
            textures=self.fx_textures,
            corpse_frame_for_type=creature_corpse_frame_for_type,
        )

    def consume_terrain_fx_batch(
        self,
        batch: TerrainFxBatch,
    ) -> None:
        if batch.is_empty():
            return
        ground = self.ground
        if ground is None or ground.texture_failed or self.fx_textures is None:
            return
        # Baking draws into the ground render target; it happens on the draw path.
        self._pending_terrain_fx_batches.append(batch)
