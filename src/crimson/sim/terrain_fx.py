from __future__ import annotations

from dataclasses import dataclass, field

import msgspec

from grim.color import RGBA
from grim.geom import Vec2

from ..effects import FxQueue, FxQueueRotated

__all__ = [
    "TerrainCorpseFx",
    "TerrainDecalFx",
    "TerrainFxBatch",
    "TerrainFxScratch",
]


class TerrainDecalFx(msgspec.Struct, frozen=True):
    effect_id: int = 0
    rotation: float = 0.0
    pos: Vec2 = Vec2()
    width: float = 0.0
    height: float = 0.0
    color: RGBA = msgspec.field(default_factory=RGBA)


class TerrainCorpseFx(msgspec.Struct, frozen=True):
    top_left: Vec2 = Vec2()
    color: RGBA = msgspec.field(default_factory=RGBA)
    rotation: float = 0.0
    scale: float = 1.0
    creature_type_id: int = 0


class TerrainFxBatch(msgspec.Struct, frozen=True):
    decals: tuple[TerrainDecalFx, ...] = ()
    corpses: tuple[TerrainCorpseFx, ...] = ()

    def is_empty(self) -> bool:
        return not self.decals and not self.corpses


@dataclass(slots=True)
class TerrainFxScratch:
    decals: FxQueue = field(default_factory=FxQueue)
    corpses: FxQueueRotated = field(default_factory=FxQueueRotated)

    def clear(self) -> None:
        self.decals.clear()
        self.corpses.clear()

    def take_batch(self) -> TerrainFxBatch:
        batch = TerrainFxBatch(
            decals=tuple(
                TerrainDecalFx(
                    effect_id=int(entry.effect_id),
                    rotation=float(entry.rotation),
                    pos=entry.pos,
                    width=float(entry.width),
                    height=float(entry.height),
                    color=entry.color,
                )
                for entry in self.decals.iter_active()
            ),
            corpses=tuple(
                TerrainCorpseFx(
                    top_left=entry.top_left,
                    color=entry.color,
                    rotation=float(entry.rotation),
                    scale=float(entry.scale),
                    creature_type_id=int(entry.creature_type_id),
                )
                for entry in self.corpses.iter_active()
            ),
        )
        self.clear()
        return batch
