from __future__ import annotations

from typing import cast

import msgspec

from ..terrain_slots import (
    TerrainSlotTriplet,
    resolve_terrain_slots,
)
from .render_resources import RenderResources


class TerrainRuntime(msgspec.Struct):
    world_size: float = 1024.0
    render_resources: RenderResources = cast(RenderResources, None)

    def apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
        seed: int,
    ) -> None:
        base, overlay, detail = resolve_terrain_slots(
            terrain_slots,
            self.render_resources.registry_texture,
        )
        self.render_resources.set_ground_textures(
            base=base,
            overlay=overlay,
            detail=detail,
        )
        self.render_resources.schedule_ground_generation(seed=seed)

    def schedule_from_rng_seed(self, *, seed: int) -> None:
        self.render_resources.schedule_ground_generation(seed=seed)

    def process_pending(self) -> None:
        self.render_resources.process_ground_pending()
