from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from crimson.net.rollback_snapshot import RollbackSnapshotCodec, RollbackSnapshotRing


@dataclass(frozen=True, slots=True)
class _TypedSnapshot:
    tick_index: int
    stage: int
    elapsed_ms: float


def test_snapshot_codec_round_trip_untyped_mapping() -> None:
    codec = RollbackSnapshotCodec[dict[str, Any]](snapshot_type=dict)
    snapshot = {"tick_index": 7, "players": [{"hp": 100.0}, {"hp": 90.0}], "flags": [1, 2, 3]}

    blob = codec.dumps(snapshot)
    restored = codec.loads(blob)

    assert restored == snapshot


def test_snapshot_codec_round_trip_typed_snapshot() -> None:
    codec = RollbackSnapshotCodec[_TypedSnapshot](snapshot_type=_TypedSnapshot)
    snapshot = _TypedSnapshot(tick_index=18, stage=2, elapsed_ms=300.0)

    blob = codec.dumps(snapshot)
    restored = codec.loads(blob)

    assert restored == snapshot


def test_snapshot_ring_store_restore_and_prune() -> None:
    ring = RollbackSnapshotRing[dict[str, int]](
        max_ticks=8,
        interval_ticks=2,
        codec=RollbackSnapshotCodec[dict[str, int]](snapshot_type=dict),
    )

    assert ring.maybe_store(tick_index=1, snapshot={"tick": 1}) is False
    assert ring.maybe_store(tick_index=2, snapshot={"tick": 2}) is True
    assert ring.maybe_store(tick_index=6, snapshot={"tick": 6}) is True
    assert ring.maybe_store(tick_index=10, snapshot={"tick": 10}, force=True) is True
    assert ring.maybe_store(tick_index=16, snapshot={"tick": 16}) is True

    assert ring.has_tick(2) is False
    assert ring.has_tick(6) is False
    assert ring.has_tick(10) is True
    assert ring.has_tick(16) is True

    assert ring.restore_exact(10) == {"tick": 10}
    assert ring.restore_latest_at_or_before(12) == (10, {"tick": 10})
    assert ring.restore_latest_at_or_before(16) == (16, {"tick": 16})
