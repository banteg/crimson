from __future__ import annotations

import pytest

from crimson.net.rollback_resync_v5 import (
    RbResyncAssemblerV5,
    RollbackResyncV5Error,
    build_rb_resync_messages,
    decode_mode_snapshot,
    encode_mode_snapshot,
)


def test_encode_decode_mode_snapshot_round_trip() -> None:
    blob = encode_mode_snapshot(
        mode="survival",
        tick_index=42,
        session_state={"elapsed_ms": 42.0},
        mode_state={"stage": 3},
        replay_state={"tick_index": 42},
    )

    decoded = decode_mode_snapshot(blob)

    assert decoded.mode == "survival"
    assert decoded.tick_index == 42
    assert decoded.mode_state["stage"] == 3


def test_resync_message_build_and_assembler_round_trip() -> None:
    payload = encode_mode_snapshot(
        mode="rush",
        tick_index=9,
        session_state={"elapsed_ms": 9.0},
        mode_state={"spawn_cooldown_ms": 0.0},
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
        mode="quests",
        tick_index=12,
        session_state={"elapsed_ms": 12.0},
        mode_state={"quest_name_timer_ms": 1.0},
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
