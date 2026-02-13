from __future__ import annotations

from crimson.net.lockstep import ClientLockstepState
from crimson.net.protocol import TickFrame


def test_client_input_batch_uses_three_tick_rolling_window() -> None:
    client = ClientLockstepState(local_slot_index=1, input_delay_ticks=2)

    batch0 = client.queue_local_input([0.0, 0.0, [1.0, 2.0], 1])
    batch1 = client.queue_local_input([0.0, 0.0, [1.0, 2.0], 2])
    batch2 = client.queue_local_input([0.0, 0.0, [1.0, 2.0], 3])

    assert [sample.tick_index for sample in batch0.samples] == [2]
    assert [sample.tick_index for sample in batch1.samples] == [3, 2]
    assert [sample.tick_index for sample in batch2.samples] == [4, 3, 2]


def test_client_consumes_tick_frames_and_reports_desync() -> None:
    client = ClientLockstepState(local_slot_index=0)

    frame0 = TickFrame(tick_index=0, frame_inputs=[[0.0, 0.0, [0.0, 0.0], 0]], command_hash="h0", state_hash="")
    client.ingest_tick_frame(frame0, now_ms=10, local_command_hash="h0")

    consumed = client.pop_canonical_frame()
    assert consumed is not None
    assert consumed.tick_index == 0

    frame1 = TickFrame(tick_index=1, frame_inputs=[[0.0, 0.0, [0.0, 0.0], 0]], command_hash="remote", state_hash="")
    client.ingest_tick_frame(frame1, now_ms=20, local_command_hash="local")

    desync = client.pop_desync_notice()
    assert desync is not None
    assert desync[0] == 1
    assert desync[1] == "remote"
    assert desync[2] == "local"


def test_client_pause_state_tracks_missing_tick_frames() -> None:
    client = ClientLockstepState(local_slot_index=0, input_stall_timeout_ms=250)

    pause = client.update_pause_state(now_ms=250)
    assert pause is not None
    assert pause.paused is True
    assert pause.reason == "waiting_tick_frame"

    frame0 = TickFrame(tick_index=0, frame_inputs=[[0.0, 0.0, [0.0, 0.0], 0]], command_hash="", state_hash="")
    client.ingest_tick_frame(frame0, now_ms=251)

    resume = client.update_pause_state(now_ms=251)
    assert resume is not None
    assert resume.paused is False
