from __future__ import annotations

from typing import cast

import msgspec

from grim.assets import TextureId, texture_for
from grim.raylib_api import rl

from ..terrain_assets import TerrainTextureId, terrain_texture_by_id
from .render_resources import RenderResources

DEFAULT_TERRAIN_IDS = (
    TerrainTextureId.Q1_BASE,
    TerrainTextureId.Q1_OVERLAY,
    TerrainTextureId.Q1_BASE,
)


def normalize_terrain_ids(
    terrain_ids: tuple[int, int, int] | None,
) -> tuple[TerrainTextureId, TerrainTextureId, TerrainTextureId]:
    if terrain_ids is None:
        return DEFAULT_TERRAIN_IDS
    try:
        return (
            TerrainTextureId(int(terrain_ids[0])),
            TerrainTextureId(int(terrain_ids[1])),
            TerrainTextureId(int(terrain_ids[2])),
        )
    except (TypeError, ValueError, IndexError):
        return DEFAULT_TERRAIN_IDS


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
        base_id, overlay_id, detail_id = normalize_terrain_ids(terrain_ids)

        def _load(texture_id: TextureId | None) -> rl.Texture | None:
            if texture_id is None:
                return None
            return texture_for(self.render_resources.assets_dir, texture_id)

        base = _load(terrain_texture_by_id(base_id))
        overlay = _load(terrain_texture_by_id(overlay_id))
        detail = _load(terrain_texture_by_id(detail_id)) or overlay or base

        if base is None and (base_id, overlay_id, detail_id) != DEFAULT_TERRAIN_IDS:
            base = _load(terrain_texture_by_id(TerrainTextureId.Q1_BASE))
            overlay = _load(terrain_texture_by_id(TerrainTextureId.Q1_OVERLAY))
            detail = _load(terrain_texture_by_id(TerrainTextureId.Q1_BASE)) or overlay or base

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
        base_key: str,
        overlay_key: str,
        base_path: str,
        overlay_path: str,
        detail_key: str | None = None,
        detail_path: str | None = None,
    ) -> None:
        base = self.render_resources.load_texture(base_key, cache_path=base_path)
        overlay = self.render_resources.load_texture(overlay_key, cache_path=overlay_path)
        detail = None
        if detail_key is not None and detail_path is not None:
            detail = self.render_resources.load_texture(detail_key, cache_path=detail_path)
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
