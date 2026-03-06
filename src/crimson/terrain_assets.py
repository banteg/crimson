from __future__ import annotations

from enum import IntEnum

from grim.assets import TextureId


class TerrainTextureId(IntEnum):
    Q1_BASE = 0
    Q1_OVERLAY = 1
    Q2_BASE = 2
    Q2_OVERLAY = 3
    Q3_BASE = 4
    Q3_OVERLAY = 5
    Q4_BASE = 6
    Q4_OVERLAY = 7
    FB_Q1 = 8
    FB_Q2 = 9
    FB_Q3 = 10
    FB_Q4 = 11


__all__ = ["TerrainTextureId", "terrain_texture_by_id"]


_TERRAIN_TEXTURES: dict[TerrainTextureId, TextureId] = {
    TerrainTextureId.Q1_BASE: TextureId.TER_Q1_BASE,
    TerrainTextureId.Q1_OVERLAY: TextureId.TER_Q1_OVERLAY,
    TerrainTextureId.Q2_BASE: TextureId.TER_Q2_BASE,
    TerrainTextureId.Q2_OVERLAY: TextureId.TER_Q2_OVERLAY,
    TerrainTextureId.Q3_BASE: TextureId.TER_Q3_BASE,
    TerrainTextureId.Q3_OVERLAY: TextureId.TER_Q3_OVERLAY,
    TerrainTextureId.Q4_BASE: TextureId.TER_Q4_BASE,
    TerrainTextureId.Q4_OVERLAY: TextureId.TER_Q4_OVERLAY,
}


def terrain_texture_by_id(terrain_id: TerrainTextureId) -> TextureId | None:
    try:
        key = TerrainTextureId(int(terrain_id))
    except ValueError:
        return None
    return _TERRAIN_TEXTURES.get(key)
