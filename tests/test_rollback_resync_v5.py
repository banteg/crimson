from __future__ import annotations

import pytest

from crimson.creatures.spawn import SpawnId
from crimson.math_parity import f32
from crimson.net.rollback_resync_v5 import (
    SCHEMA_VERSION,
    QuestsRuntimeSnapshotV2,
    QuestsStateSnapshotV2,
    RbResyncAssemblerV5,
    RollbackResyncV5Error,
    RushRuntimeSnapshotV2,
    RushStateSnapshotV2,
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    build_rb_resync_messages,
    decode_mode_snapshot,
    encode_mode_snapshot,
)
from crimson.quests.types import SpawnEntry
from grim.geom import Vec2


def test_encode_decode_mode_snapshot_round_trip() -> None:
    blob = encode_mode_snapshot(
        snapshot=SurvivalStateSnapshotV2(
            tick_index=42,
            runtime_state=SurvivalRuntimeSnapshotV2(
                elapsed_ms=42.0,
                stage=3,
                spawn_cooldown_ms=0.100000001,
                perk_pending_count=0,
            ),
        ),
    )

    decoded = decode_mode_snapshot(blob)

    assert isinstance(decoded, SurvivalStateSnapshotV2)
    assert decoded.mode == "survival"
    assert decoded.tick_index == 42
    assert decoded.runtime_state.stage == 3
    assert decoded.runtime_state.spawn_cooldown_ms == float(f32(0.100000001))


def test_resync_message_build_and_assembler_round_trip() -> None:
    payload = encode_mode_snapshot(
        snapshot=RushStateSnapshotV2(
            tick_index=9,
            runtime_state=RushRuntimeSnapshotV2(
                elapsed_ms=9.0,
                spawn_cooldown_ms=0.0,
                kill_count=0,
            ),
        ),
    )
    stream = build_rb_resync_messages(request_id="rq", snapshot_tick=9, snapshot_blob=payload)

    assembler = RbResyncAssemblerV5()
    assembler.begin(stream.begin)
    for chunk in stream.chunks:
        assembler.push_chunk(chunk)
    tick_index, rebuilt = assembler.finalize(stream.commit)

    assert tick_index == 9
    assert rebuilt == payload


def test_resync_assembler_rejects_commit_tick_mismatch() -> None:
    spawn_entries = (
        SpawnEntry(
            pos=Vec2(12.5, 48.0),
            heading=90.0,
            spawn_id=SpawnId.ALIEN_RANDOM_06,
            trigger_ms=1500,
            count=2,
        ),
    )
    payload = encode_mode_snapshot(
        snapshot=QuestsStateSnapshotV2(
            tick_index=12,
            runtime_state=QuestsRuntimeSnapshotV2(
                elapsed_ms=12.0,
                spawn_entries=spawn_entries,
                spawn_timeline_ms=0.0,
                no_creatures_timer_ms=0.0,
                completion_transition_ms=0.0,
                perk_pending_count=0,
            ),
        ),
    )
    stream = build_rb_resync_messages(request_id="rq2", snapshot_tick=12, snapshot_blob=payload)

    assembler = RbResyncAssemblerV5()
    assembler.begin(stream.begin)
    for chunk in stream.chunks:
        assembler.push_chunk(chunk)

    broken_commit = type(stream.commit)(
        request_id=stream.commit.request_id,
        snapshot_tick=stream.commit.snapshot_tick + 1,
    )
    with pytest.raises(RollbackResyncV5Error):
        assembler.finalize(broken_commit)


def test_quest_snapshot_round_trip_preserves_spawn_entries() -> None:
    spawn_entries = (
        SpawnEntry(
            pos=Vec2(128.0, 256.0),
            heading=180.0,
            spawn_id=SpawnId.SPIDER_SP1_RANDOM_03,
            trigger_ms=2000,
            count=3,
        ),
    )
    blob = encode_mode_snapshot(
        snapshot=QuestsStateSnapshotV2(
            tick_index=7,
            runtime_state=QuestsRuntimeSnapshotV2(
                elapsed_ms=1200.0,
                spawn_entries=spawn_entries,
                spawn_timeline_ms=900.0,
                no_creatures_timer_ms=300.0,
                completion_transition_ms=150.0,
                perk_pending_count=1,
            ),
        ),
    )

    decoded = decode_mode_snapshot(blob)

    assert isinstance(decoded, QuestsStateSnapshotV2)
    assert decoded.schema_version == SCHEMA_VERSION
    assert decoded.runtime_state.spawn_entries == spawn_entries
