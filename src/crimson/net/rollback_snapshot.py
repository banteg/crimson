from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import pickle
from typing import Generic, TypeVar


SnapshotT = TypeVar("SnapshotT")


@dataclass(slots=True)
class RollbackSnapshotCodec(Generic[SnapshotT]):
    """Serialize rollback snapshots as deterministic pickle blobs."""

    protocol: int = pickle.HIGHEST_PROTOCOL

    def dumps(self, snapshot: SnapshotT) -> bytes:
        return pickle.dumps(snapshot, protocol=int(self.protocol))

    def loads(self, blob: bytes) -> SnapshotT:
        return pickle.loads(blob)


@dataclass(slots=True)
class RollbackSnapshotRing(Generic[SnapshotT]):
    """Store periodic snapshots for rollback and reconnect restore."""

    max_ticks: int
    interval_ticks: int = 4
    codec: RollbackSnapshotCodec[SnapshotT] = field(default_factory=RollbackSnapshotCodec)
    _by_tick: OrderedDict[int, bytes] = field(default_factory=OrderedDict)

    def clear(self) -> None:
        self._by_tick.clear()

    def maybe_store(self, *, tick_index: int, snapshot: SnapshotT, force: bool = False) -> bool:
        tick = int(tick_index)
        if tick < 0:
            return False
        interval = max(1, int(self.interval_ticks))
        if (not bool(force)) and (tick % interval) != 0:
            return False
        self._by_tick[tick] = self.codec.dumps(snapshot)
        self._by_tick.move_to_end(tick, last=True)
        self._prune(max_tick=tick)
        return True

    def has_tick(self, tick_index: int) -> bool:
        return int(tick_index) in self._by_tick

    def restore_exact(self, tick_index: int) -> SnapshotT | None:
        blob = self._by_tick.get(int(tick_index))
        if blob is None:
            return None
        return self.codec.loads(blob)

    def restore_latest_at_or_before(self, tick_index: int) -> tuple[int, SnapshotT] | None:
        target = int(tick_index)
        candidate: int | None = None
        for tick in self._by_tick.keys():
            if int(tick) <= int(target):
                candidate = int(tick)
            else:
                break
        if candidate is None:
            return None
        blob = self._by_tick.get(int(candidate))
        if blob is None:
            return None
        return int(candidate), self.codec.loads(blob)

    def _prune(self, *, max_tick: int) -> None:
        keep_from = int(max_tick) - max(1, int(self.max_ticks))
        for tick in list(self._by_tick.keys()):
            if int(tick) >= int(keep_from):
                continue
            self._by_tick.pop(int(tick), None)


__all__ = ["RollbackSnapshotCodec", "RollbackSnapshotRing"]
