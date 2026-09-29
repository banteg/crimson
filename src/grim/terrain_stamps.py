from __future__ import annotations

from typing import NamedTuple

import msgspec


class TerrainStamp(NamedTuple):
    """One `grim_draw_quad_xy` call of terrain generation, before `position *= inv_scale`.

    `rotation` is the float32 radians passed to `grim_set_rotation`; `x`/`y` are the
    quad's top-left in 1024-unit terrain space and already include the native -64 overscan.
    """

    rotation: float
    x: float
    y: float


type TerrainStampLayer = tuple[TerrainStamp, ...]


class TerrainLayers(msgspec.Struct, frozen=True):
    """The three stamp batches of one terrain generation, in draw order."""

    base: TerrainStampLayer
    overlay: TerrainStampLayer
    detail: TerrainStampLayer
