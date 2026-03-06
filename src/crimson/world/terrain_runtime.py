from __future__ import annotations

from typing import cast

import msgspec

from grim.assets import TextureId

from ..terrain_slots import (
    DEFAULT_TERRAIN_TEXTURE_IDS,
    TerrainSlotTriplet,
    terrain_slots_to_texture_ids,
)
from .render_resources import RenderResources


class TerrainRuntime(msgspec.Struct):
    world_size: float = 1024.0
    render_resources: RenderResources = cast(RenderResources, None)

    def _apply_ground_texture_ids(
        self,
        *,
        base_texture_id: TextureId,
        overlay_texture_id: TextureId,
        detail_texture_id: TextureId | None = None,
        fallback_to_default: bool = False,
    ) -> bool:
        base = self.render_resources.load_texture(base_texture_id)
        overlay = self.render_resources.load_texture(overlay_texture_id)
        detail = None if detail_texture_id is None else self.render_resources.load_texture(detail_texture_id)
        if detail is None:
            detail = overlay or base

        requested = (base_texture_id, overlay_texture_id, detail_texture_id or overlay_texture_id)
        if fallback_to_default and base is None and requested != DEFAULT_TERRAIN_TEXTURE_IDS:
            base = self.render_resources.load_texture(DEFAULT_TERRAIN_TEXTURE_IDS[0])
            overlay = self.render_resources.load_texture(DEFAULT_TERRAIN_TEXTURE_IDS[1])
            detail = self.render_resources.load_texture(DEFAULT_TERRAIN_TEXTURE_IDS[2]) or overlay or base

        if base is None:
            return False

        self.render_resources.set_ground_textures(
            base=base,
            overlay=overlay,
            detail=detail,
        )
        return True

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
        seed: int,
        layers: int = 3,
    ) -> None:
        base_texture_id, overlay_texture_id, detail_texture_id = terrain_slots_to_texture_ids(terrain_slots)
        if not self._apply_ground_texture_ids(
            base_texture_id=base_texture_id,
            overlay_texture_id=overlay_texture_id,
            detail_texture_id=detail_texture_id,
            fallback_to_default=True,
        ):
            return
        self.render_resources.schedule_ground_generation(seed=int(seed), layers=int(layers))

    def set_terrain_slots(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
    ) -> None:
        base_texture_id, overlay_texture_id, detail_texture_id = terrain_slots_to_texture_ids(terrain_slots)
        self._apply_ground_texture_ids(
            base_texture_id=base_texture_id,
            overlay_texture_id=overlay_texture_id,
            detail_texture_id=detail_texture_id,
        )

    def set_ground_textures(
        self,
        *,
        base_texture_id: TextureId,
        overlay_texture_id: TextureId,
        detail_texture_id: TextureId | None = None,
    ) -> None:
        self._apply_ground_texture_ids(
            base_texture_id=base_texture_id,
            overlay_texture_id=overlay_texture_id,
            detail_texture_id=detail_texture_id,
        )

    def schedule_from_rng_seed(self, *, seed: int, layers: int = 3) -> None:
        self.render_resources.schedule_ground_generation(seed=int(seed), layers=int(layers))

    def process_pending(self) -> None:
        self.render_resources.process_ground_pending()
