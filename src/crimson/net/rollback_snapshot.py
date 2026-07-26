from __future__ import annotations

from collections import OrderedDict
from typing import Any, TypeVar, cast

import msgspec

SnapshotT = TypeVar("SnapshotT")


class RollbackSnapshotCodec[SnapshotT](msgspec.Struct):
    """Serialize rollback snapshots as deterministic msgpack blobs."""

    snapshot_type: type[SnapshotT]
    _encoder: msgspec.msgpack.Encoder = cast(msgspec.msgpack.Encoder, None)
    _decoder: msgspec.msgpack.Decoder = cast(msgspec.msgpack.Decoder, None)

    def __post_init__(self) -> None:
        self._encoder = msgspec.msgpack.Encoder()
        self._decoder = msgspec.msgpack.Decoder(type=cast(Any, self.snapshot_type))

    def dumps(self, snapshot: SnapshotT) -> bytes:
        return self._encoder.encode(snapshot)

    def loads(self, blob: bytes) -> SnapshotT:
        return cast(SnapshotT, self._decoder.decode(blob))


class RollbackSnapshotRing[SnapshotT](msgspec.Struct):
    """Store periodic snapshots for rollback and reconnect restore."""

    max_ticks: int
    codec: RollbackSnapshotCodec[SnapshotT]
    interval_ticks: int = 4
    _by_tick: OrderedDict[int, bytes] = msgspec.field(default_factory=OrderedDict)

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
        for tick in self._by_tick:
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
