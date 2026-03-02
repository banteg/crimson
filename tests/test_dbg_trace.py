from __future__ import annotations

from pathlib import Path

import msgspec
import pytest

from crimson.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta, channel_versions_for
from crimson.dbg.trace import TraceError, TraceReader, write_trace


def _meta() -> TraceMeta:
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc="2026-02-24T00:00:00+00:00",
        producer={"impl": "python", "impl_version": "test", "platform": "darwin", "arch": "x86_64"},
        source={"kind": "unit_test", "sha256": "0" * 64},
        channels=["checkpoint"],
        channel_versions=channel_versions_for(("checkpoint",)),
        tick_range={"start_tick": 0, "end_tick": 2, "tick_count": 3},
        config={},
    )


def test_trace_roundtrip_random_access(tmp_path: Path) -> None:
    rows = [
        TickRecord(
            tick_index=0,
            elapsed_ms=0,
            dt_ms_i32=16,
            mode_id=1,
            phase_markers=[],
            channels={"checkpoint": {"score_xp": 0}},
        ),
        TickRecord(
            tick_index=1,
            elapsed_ms=16,
            dt_ms_i32=16,
            mode_id=1,
            phase_markers=[],
            channels={"checkpoint": {"score_xp": 5}},
        ),
        TickRecord(
            tick_index=2,
            elapsed_ms=33,
            dt_ms_i32=16,
            mode_id=1,
            phase_markers=[],
            channels={"checkpoint": {"score_xp": 9}},
        ),
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


def test_trace_reader_rejects_old_schema_version(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_schema_v1.cdt"
    meta = TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=1,
        created_utc="2026-02-24T00:00:00+00:00",
        producer={"impl": "python", "impl_version": "test", "platform": "darwin", "arch": "x86_64"},
        source={"kind": "unit_test", "sha256": "1" * 64},
        channels=["checkpoint"],
        channel_versions=channel_versions_for(("checkpoint",)),
        tick_range={"start_tick": 0, "end_tick": 0, "tick_count": 1},
        config={},
    )
    rows = [
        TickRecord(
            tick_index=0,
            elapsed_ms=0,
            dt_ms_i32=16,
            mode_id=1,
            phase_markers=[],
            channels={"checkpoint": {"score_xp": 0}},
        ),
    ]
    write_trace(out_path, meta=meta, ticks=rows, chunk_ticks=1)

    with pytest.raises(TraceError, match="unsupported trace schema version"):
        with TraceReader(out_path):
            pass


def test_trace_reader_rejects_unknown_schema_version(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_schema_bad.cdt"
    meta = TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=99,
        created_utc="2026-02-24T00:00:00+00:00",
        producer={"impl": "python", "impl_version": "test", "platform": "darwin", "arch": "x86_64"},
        source={"kind": "unit_test", "sha256": "2" * 64},
        channels=["checkpoint"],
        channel_versions=channel_versions_for(("checkpoint",)),
        tick_range={"start_tick": 0, "end_tick": 0, "tick_count": 1},
        config={},
    )
    rows = [
        TickRecord(
            tick_index=0,
            elapsed_ms=0,
            dt_ms_i32=16,
            mode_id=1,
            phase_markers=[],
            channels={"checkpoint": {"score_xp": 0}},
        ),
    ]
    write_trace(out_path, meta=meta, ticks=rows, chunk_ticks=1)

    with pytest.raises(TraceError, match="unsupported trace schema version"):
        with TraceReader(out_path):
            pass
