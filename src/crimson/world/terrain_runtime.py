from __future__ import annotations

from typing import cast

import msgspec

from grim.assets import TextureId

from ..terrain_assets import TerrainTextureId
from .render_resources import RenderResources

DEFAULT_TERRAIN_IDS = (
    TextureId.TER_Q1_BASE,
    TextureId.TER_Q1_OVERLAY,
    TextureId.TER_Q1_BASE,
)
_TEXTURE_ID_BY_TERRAIN_ID: dict[int, TextureId] = {
    int(TerrainTextureId.Q1_BASE): TextureId.TER_Q1_BASE,
    int(TerrainTextureId.Q1_OVERLAY): TextureId.TER_Q1_OVERLAY,
    int(TerrainTextureId.Q2_BASE): TextureId.TER_Q2_BASE,
    int(TerrainTextureId.Q2_OVERLAY): TextureId.TER_Q2_OVERLAY,
    int(TerrainTextureId.Q3_BASE): TextureId.TER_Q3_BASE,
    int(TerrainTextureId.Q3_OVERLAY): TextureId.TER_Q3_OVERLAY,
    int(TerrainTextureId.Q4_BASE): TextureId.TER_Q4_BASE,
    int(TerrainTextureId.Q4_OVERLAY): TextureId.TER_Q4_OVERLAY,
}


def normalize_terrain_ids(
    terrain_ids: tuple[int, int, int] | None,
) -> tuple[TextureId, TextureId, TextureId]:
    if terrain_ids is None:
        return DEFAULT_TERRAIN_IDS
    try:
        base = _TEXTURE_ID_BY_TERRAIN_ID[int(terrain_ids[0])]
        overlay = _TEXTURE_ID_BY_TERRAIN_ID[int(terrain_ids[1])]
        detail = _TEXTURE_ID_BY_TERRAIN_ID[int(terrain_ids[2])]
    except (KeyError, TypeError, ValueError, IndexError):
        return DEFAULT_TERRAIN_IDS
    return base, overlay, detail


class TerrainRuntime(msgspec.Struct):
    world_size: float = 1024.0
    render_resources: RenderResources = cast(RenderResources, None)

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_ids: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        base_texture_id, overlay_texture_id, detail_texture_id = normalize_terrain_ids(terrain_ids)
        base = self.render_resources.load_texture(base_texture_id)
        overlay = self.render_resources.load_texture(overlay_texture_id)
        detail = self.render_resources.load_texture(detail_texture_id) or overlay or base

        if base is None and (base_texture_id, overlay_texture_id, detail_texture_id) != DEFAULT_TERRAIN_IDS:
            base = self.render_resources.load_texture(DEFAULT_TERRAIN_IDS[0])
            overlay = self.render_resources.load_texture(DEFAULT_TERRAIN_IDS[1])
            detail = self.render_resources.load_texture(DEFAULT_TERRAIN_IDS[2]) or overlay or base

        if base is None:
            return

        self.render_resources.set_ground_textures(
            base=base,
            overlay=overlay,
            detail=detail,
        )
        self.render_resources.schedule_ground_generation(seed=int(seed), layers=int(layers))

    def set_terrain(
        self,
        *,
        base_texture_id: TextureId,
        overlay_texture_id: TextureId,
        detail_texture_id: TextureId | None = None,
    ) -> None:
        base = self.render_resources.load_texture(base_texture_id)
        overlay = self.render_resources.load_texture(overlay_texture_id)
        detail = None if detail_texture_id is None else self.render_resources.load_texture(detail_texture_id)
        if detail is None:
            detail = overlay or base
        if base is None:
            return
        self.render_resources.set_ground_textures(
            base=base,
            overlay=overlay,
            detail=detail,
        )

    def schedule_from_rng_seed(self, *, seed: int, layers: int = 3) -> None:
        self.render_resources.schedule_ground_generation(seed=int(seed), layers=int(layers))

    def process_pending(self) -> None:
        self.render_resources.process_ground_pending()
