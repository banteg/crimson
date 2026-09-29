from __future__ import annotations

from typing import cast

import msgspec

from ..sim.terrain_generate import TerrainSetup
from ..terrain_slots import resolve_terrain_slots
from .render_resources import RenderResources


class TerrainRuntime(msgspec.Struct):
    render_resources: RenderResources = cast(RenderResources, None)
    # The setup the ground was last drawn from; applying it again draws the same stamps.
    setup: TerrainSetup | None = None

    def apply_terrain_setup(self, setup: TerrainSetup) -> None:
        base, overlay, detail = resolve_terrain_slots(
            setup.terrain_slots,
            self.render_resources.registry_texture,
        )
        self.render_resources.set_ground_textures(
            base=base,
            overlay=overlay,
            detail=detail,
        )
        self.render_resources.schedule_ground_stamps(setup.layers)
        self.setup = setup

    def process_pending(self) -> None:
        self.render_resources.process_ground_pending()
