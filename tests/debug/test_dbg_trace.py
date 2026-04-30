from __future__ import annotations

from pathlib import Path

import msgspec
import pytest

from crimson.dbg.canonical_channels import (
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotVec2,
)
from crimson.dbg.schema import (
    TRACE_FORMAT_VERSION,
    TRACE_REQUIRED_CHANNELS,
    TRACE_SCHEMA_VERSION,
    ReplayTickChannels,
    TickRecord,
    TraceConfig,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
    channel_versions_for,
)
from crimson.dbg.trace import TraceError, TraceReader, write_trace
from crimson.persistence.save_status import GameStatusData
from crimson.replay.checkpoints import ReplayCheckpoint, ReplayDeathLedgerEntry


def _meta() -> TraceMeta:
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc="2026-02-24T00:00:00+00:00",
        producer=TraceProducer(impl="python", impl_version="test", platform="darwin", arch="x86_64"),
        source=TraceSource(kind="unit_test", sha256="0" * 64),
        channels=[*TRACE_REQUIRED_CHANNELS],
        channel_versions=channel_versions_for(TRACE_REQUIRED_CHANNELS),
        tick_range=TraceTickRange(start_tick=0, end_tick=2, tick_count=3),
        config=TraceConfig(),
        status=GameStatusData(),
    )


def _channels(*, tick_index: int, elapsed_ms: int, score_xp: int) -> ReplayTickChannels:
    return ReplayTickChannels(
        checkpoint=ReplayCheckpoint(
            tick_index=int(tick_index),
            rng_state=0,
            elapsed_ms=int(elapsed_ms),
            score_xp=int(score_xp),
            kills=0,
            creature_count=0,
            perk_pending=0,
            players=[],
            bonus_timers={},
            deaths=[
                ReplayDeathLedgerEntry(
                    creature_index=3,
                    type_id=18,
                    reward_value=75.0,
                    xp_awarded=10,
                    owner_id=-1,
                ),
            ],
        ),
        sim_state=SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=1,
                quest_stage_major=-1,
                quest_stage_minor=-1,
                perk_pending_count=0,
                perk_choices_dirty=False,
                bonus_timers=SnapshotBonusTimers(
                    weapon_power_up_ms=0,
                    reflex_boost_ms=0,
                    energizer_ms=0,
                    double_experience_ms=0,
                    freeze_ms=0,
                ),
            ),
            players=[],
        ),
        entity_samples=EntitySamplesSnapshot(
            creatures=[],
            projectiles=[
                ProjectileEntitySample(
                    uid=11,
                    generation=1,
                    pool_kind="projectile",
                    index=2,
                    active=True,
                    type_id=4,
                    angle=0.25,
                    pos=SnapshotVec2(x=1.0, y=2.0),
                    vel=SnapshotVec2(x=3.0, y=4.0),
                    life_timer=0.5,
                    speed_scale=1.0,
                    damage_pool=8.0,
                    hit_radius=1.5,
                    travel_budget=9.0,
                    owner_id=-100,
                ),
            ],
            secondary_projectiles=[
                SecondaryProjectileEntitySample(
                    uid=21,
                    generation=1,
                    pool_kind="secondary_projectile",
                    index=5,
                    active=True,
                    type_id=7,
                    angle=0.5,
                    pos=SnapshotVec2(x=5.0, y=6.0),
                    vel=SnapshotVec2(x=7.0, y=8.0),
                    speed=3.0,
                    trail_timer=0.25,
                    owner_id=13,
                    target_id=99,
                ),
            ],
            bonuses=[],
        ),
        rng_stream=[
            RngStreamRow(
                tick_call_index=1,
                value_15=28052,
                state_before_u32=2427270273,
                state_after_u32=3985917248,
                caller=0x004281A2,
            ),
        ],
        timing_samples=[],
    )


def _row(*, tick_index: int, elapsed_ms: int, score_xp: int) -> TickRecord:
    return TickRecord(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        dt_ms_i32=16,
        mode_id=1,
        channels=_channels(tick_index=int(tick_index), elapsed_ms=int(elapsed_ms), score_xp=int(score_xp)),
    )


def test_trace_roundtrip_random_access(tmp_path: Path) -> None:
    rows = [
        _row(tick_index=0, elapsed_ms=0, score_xp=0),
        _row(tick_index=1, elapsed_ms=16, score_xp=5),
        _row(tick_index=2, elapsed_ms=33, score_xp=9),
    ]
    out_path = tmp_path / "trace.cdt"
    summary = write_trace(out_path, meta=_meta(), ticks=rows, chunk_ticks=2)

    assert summary.footer.tick_count == 3
    assert summary.footer.channel_tick_counts["checkpoint"] == 3
    assert summary.footer.channel_row_counts["rng_stream"] == 3
    assert summary.footer.channel_row_counts["timing_samples"] == 0
    assert out_path.exists()

    with TraceReader(out_path) as reader:
        assert reader.meta.trace_format_version == TRACE_FORMAT_VERSION
        tick1 = reader.tick(1)
        assert tick1 is not None
        assert tick1.elapsed_ms == 16
        assert tick1.channels.rng_stream[0].caller == 0x004281A2
        window = list(reader.iter_ticks(tick_start=1, tick_end=2))
        assert [row.tick_index for row in window] == [1, 2]


def test_trace_meta_rejects_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "trace_format_version": TRACE_FORMAT_VERSION,
            "trace_schema_version": TRACE_SCHEMA_VERSION,
            "created_utc": "2026-02-24T00:00:00+00:00",
            "producer": {"impl": "python", "impl_version": "", "platform": "darwin", "arch": "x86_64"},
            "source": {"kind": "unit_test", "sha256": "0" * 64},
            "channels": ["checkpoint"],
            "channel_versions": {
                "checkpoint": 1,
                "sim_state": 1,
                "entity_samples": 1,
                "rng_stream": 1,
                "timing_samples": 1,
            },
            "tick_range": {"start_tick": 0, "end_tick": 0, "tick_count": 1},
            "config": {},
            "future_field": {"nested": True},
        },
    )
    with pytest.raises(msgspec.ValidationError, match="future_field"):
        msgspec.msgpack.decode(payload, type=TraceMeta)


def test_tick_record_decodes_with_unknown_fields() -> None:
    payload = msgspec.msgpack.encode(
        {
            "tick_index": 7,
            "elapsed_ms": 112,
            "dt_ms_i32": 16,
            "mode_id": 2,
            "channels": msgspec.to_builtins(_channels(tick_index=7, elapsed_ms=112, score_xp=42)),
            "future_tick_field": "ignored",
        },
    )
    tick = msgspec.msgpack.decode(payload, type=TickRecord)
    assert tick.tick_index == 7
    assert tick.channels.checkpoint.deaths[0].owner_id == -1
    assert tick.channels.entity_samples.projectiles[0].owner_id == -100
    assert tick.channels.entity_samples.secondary_projectiles[0].owner_id == 13


def test_trace_reader_rejects_old_schema_version(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_schema_v1.cdt"
    meta = TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=1,
        created_utc="2026-02-24T00:00:00+00:00",
        producer=TraceProducer(impl="python", impl_version="test", platform="darwin", arch="x86_64"),
        source=TraceSource(kind="unit_test", sha256="1" * 64),
        channels=[*TRACE_REQUIRED_CHANNELS],
        channel_versions=channel_versions_for(TRACE_REQUIRED_CHANNELS),
        tick_range=TraceTickRange(start_tick=0, end_tick=0, tick_count=1),
        config=TraceConfig(),
    )
    rows = [_row(tick_index=0, elapsed_ms=0, score_xp=0)]
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
        producer=TraceProducer(impl="python", impl_version="test", platform="darwin", arch="x86_64"),
        source=TraceSource(kind="unit_test", sha256="2" * 64),
        channels=[*TRACE_REQUIRED_CHANNELS],
        channel_versions=channel_versions_for(TRACE_REQUIRED_CHANNELS),
        tick_range=TraceTickRange(start_tick=0, end_tick=0, tick_count=1),
        config=TraceConfig(),
    )
    rows = [_row(tick_index=0, elapsed_ms=0, score_xp=0)]
    write_trace(out_path, meta=meta, ticks=rows, chunk_ticks=1)

    with pytest.raises(TraceError, match="unsupported trace schema version"):
        with TraceReader(out_path):
            pass


def test_write_trace_rejects_empty_ticks(tmp_path: Path) -> None:
    out_path = tmp_path / "trace_empty.cdt"
    with pytest.raises(TraceError, match="trace must contain at least one tick"):
        write_trace(out_path, meta=_meta(), ticks=[], chunk_ticks=1)
