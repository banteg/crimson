from __future__ import annotations

from crimson.render.rtx.material_history import MaterialHistory
from crimson.sim.terrain_fx import TerrainFxBatch


def test_pending_history_spills_preserves_order_and_releases_storage() -> None:
    history = MaterialHistory(ram_bytes=128)
    batches = [TerrainFxBatch(elapsed_s=i * .25) for i in range(500)]
    history.extend(batches)
    assert len(history) == len(batches)
    assert list(history) == batches
    assert list(history) == batches  # Iteration can restart without an in-memory index.
    stream = history._file
    assert stream is not None and stream.name is not None
    chunks = list(history.chunks())
    assert max(map(len, chunks)) <= 128
    assert [batch for chunk in chunks for batch in chunk] == batches
    history.clear()
    assert stream.closed and len(history) == 0 and list(history) == []
    history.append(batches[0])
    assert list(history) == batches[:1]
    history.clear()


def test_pending_history_chunks_bound_epoch_span() -> None:
    history = MaterialHistory()
    try:
        batches = [TerrainFxBatch(elapsed_s=time) for time in (0, 90, 180, 181, 36000)]
        history.extend(batches)
        chunks = list(history.chunks())
        assert [batch for chunk in chunks for batch in chunk] == batches
        assert all(chunk[-1].elapsed_s - chunk[0].elapsed_s <= 180 for chunk in chunks)
    finally:
        history.clear()
