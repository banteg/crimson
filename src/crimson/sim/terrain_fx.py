from __future__ import annotations

from dataclasses import dataclass, field

import msgspec

from ..effects import FxQueue, FxQueueEntry, FxQueueRotated, FxQueueRotatedEntry

__all__ = [
    "TerrainFxBatch",
    "TerrainFxScratch",
]


class TerrainFxBatch(msgspec.Struct, frozen=True):
    """A tick's `fx_queue` and `fx_queue_rotated` entries, copied out for the ground bake."""

    decals: tuple[FxQueueEntry, ...] = ()
    corpses: tuple[FxQueueRotatedEntry, ...] = ()

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
        # The queues reuse their entry slots, so the batch keeps copies.
        batch = TerrainFxBatch(
            decals=tuple(msgspec.structs.replace(entry) for entry in self.decals.iter_active()),
            corpses=tuple(msgspec.structs.replace(entry) for entry in self.corpses.iter_active()),
        )
        self.clear()
        return batch
