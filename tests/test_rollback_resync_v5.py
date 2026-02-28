from __future__ import annotations

import pytest

from crimson.math_parity import f32
from crimson.net.rollback_resync_v5 import (
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


def test_resync_assembler_rejects_checksum_mismatch() -> None:
    payload = encode_mode_snapshot(
        snapshot=QuestsStateSnapshotV2(
            tick_index=12,
            runtime_state=QuestsRuntimeSnapshotV2(
                elapsed_ms=12.0,
                spawn_timeline_ms=0.0,
                no_creatures_timer_ms=0.0,
                completion_transition_ms=0.0,
                quest_name_timer_ms=1.0,
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
        snapshot_tick=stream.commit.snapshot_tick,
        payload_sha256="0" * 64,
    )
    with pytest.raises(RollbackResyncV5Error):
        assembler.finalize(broken_commit)
