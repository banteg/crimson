from __future__ import annotations

import pytest

from crimson.net.adapter import ResyncFailureTracker
from crimson.net.resync import ResyncAssembler, ResyncBuildError, build_resync_messages


def test_resync_bundle_round_trip_rebuilds_replay_and_checkpoints() -> None:
    replay_blob = b"replay-bytes-123"
    checkpoints_blob = b"checkpoints-bytes-456"

    begin, chunks, commit = build_resync_messages(
        replay_blob=replay_blob,
        checkpoints_blob=checkpoints_blob,
        tick_index=777,
        chunk_size=8,
        stream_id="stream-1",
    )

    assembler = ResyncAssembler()
    assembler.ingest_begin(begin)

    # Intentionally out-of-order to exercise chunk indexing.
    for chunk in reversed(chunks):
        assert assembler.ingest_chunk(chunk) is True

    assert assembler.ingest_commit(commit) is True
    assert assembler.ready() is True

    rebuilt_replay, rebuilt_checkpoints, rebuilt_tick = assembler.rebuild_payload()

    assert rebuilt_replay == replay_blob
    assert rebuilt_checkpoints == checkpoints_blob
    assert rebuilt_tick == 777


def test_resync_rebuild_fails_when_chunks_missing() -> None:
    begin, chunks, commit = build_resync_messages(
        replay_blob=b"a",
        checkpoints_blob=b"b",
        tick_index=1,
        chunk_size=1,
        stream_id="stream-2",
    )

    assembler = ResyncAssembler()
    assembler.ingest_begin(begin)
    assembler.ingest_chunk(chunks[0])
    assembler.ingest_commit(commit)

    # Drop one chunk (when available) and ensure rebuild rejects incomplete payload.
    if begin.total_chunks > 1:
        with pytest.raises(ResyncBuildError, match="missing chunks"):
            assembler.rebuild_payload()


def test_resync_failure_tracker_aborts_after_two_failures() -> None:
    tracker = ResyncFailureTracker(max_failures_per_match=2)

    assert tracker.note_failure() is False
    assert tracker.note_failure() is True

    tracker.reset()
    assert tracker.failures == 0
