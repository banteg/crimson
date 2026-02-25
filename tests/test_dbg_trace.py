from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta
from crimson.dbg.trace import TraceReader, write_trace


def _meta() -> TraceMeta:
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc="2026-02-24T00:00:00+00:00",
        producer={"impl": "python", "impl_version": "test", "platform": "darwin", "arch": "x86_64"},
        source={"kind": "unit_test", "sha256": "0" * 64},
        channels=["checkpoint"],
        channel_versions={"checkpoint": 1},
        tick_range={"start_tick": 0, "end_tick": 2, "tick_count": 3},
        config={},
    )


def test_trace_roundtrip_random_access(tmp_path: Path) -> None:
    rows = [
        TickRecord(tick_index=0, elapsed_ms=0, mode_id=1, channels={"checkpoint": {"score_xp": 0}}),
        TickRecord(tick_index=1, elapsed_ms=16, mode_id=1, channels={"checkpoint": {"score_xp": 5}}),
        TickRecord(tick_index=2, elapsed_ms=33, mode_id=1, channels={"checkpoint": {"score_xp": 9}}),
    ]
    out_path = tmp_path / "trace.cdt"
    summary = write_trace(out_path, meta=_meta(), ticks=rows, chunk_ticks=2)

    assert summary.footer.tick_count == 3
    assert out_path.exists()

    with TraceReader(out_path) as reader:
        assert reader.meta.trace_format_version == TRACE_FORMAT_VERSION
        tick1 = reader.tick(1)
        assert tick1 is not None
        assert tick1.elapsed_ms == 16
        window = list(reader.iter_ticks(tick_start=1, tick_end=2))
        assert [row.tick_index for row in window] == [1, 2]


def test_trace_meta_decodes_with_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "trace_format_version": TRACE_FORMAT_VERSION,
            "trace_schema_version": TRACE_SCHEMA_VERSION,
            "created_utc": "2026-02-24T00:00:00+00:00",
            "producer": {"impl": "python"},
            "source": {"kind": "unit_test"},
            "channels": ["checkpoint"],
            "channel_versions": {"checkpoint": 1},
            "tick_range": {"start_tick": 0, "end_tick": 0, "tick_count": 1},
            "config": {},
            "future_field": {"nested": True},
        },
    )
    meta = msgspec.msgpack.decode(payload, type=TraceMeta)
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION


def test_tick_record_decodes_with_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "tick_index": 7,
            "elapsed_ms": 112,
            "dt_ms_i32": 16,
            "mode_id": 2,
            "phase_markers": ["pre", "post"],
            "channels": {"checkpoint": {"score_xp": 42}},
            "future_tick_field": "ignored",
        },
    )
    tick = msgspec.msgpack.decode(payload, type=TickRecord)
    assert tick.tick_index == 7
