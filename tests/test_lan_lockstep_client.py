from __future__ import annotations

from crimson.net.lockstep_protocol import TickFrame
from crimson.net.lockstep_state import ClientLockstepState


def test_client_input_batch_uses_three_tick_rolling_window() -> None:
    client = ClientLockstepState(local_slot_index=1, input_delay_ticks=2)

    batch0 = client.queue_local_input([0.0, 0.0, 1.0, 2.0, 1])
    client.ingest_tick_frame(TickFrame(tick_index=0, frame_inputs=[], state_hash=""), now_ms=0)
    assert client.pop_canonical_frame() is not None
    batch1 = client.queue_local_input([0.0, 0.0, 1.0, 2.0, 2])
    client.ingest_tick_frame(TickFrame(tick_index=1, frame_inputs=[], state_hash=""), now_ms=0)
    assert client.pop_canonical_frame() is not None
    batch2 = client.queue_local_input([0.0, 0.0, 1.0, 2.0, 3])

    assert [sample.tick_index for sample in batch0.samples] == [2]
    assert [sample.tick_index for sample in batch1.samples] == [3, 2]
    assert [sample.tick_index for sample in batch2.samples] == [4, 3, 2]


def test_client_pause_state_tracks_missing_tick_frames() -> None:
    client = ClientLockstepState(local_slot_index=0, input_stall_timeout_ms=250)

    pause = client.update_pause_state(now_ms=250)
    assert pause is not None
    assert pause.paused is True
    assert pause.reason == "waiting_tick_frame"

    frame0 = TickFrame(tick_index=0, frame_inputs=[[0.0, 0.0, 0.0, 0.0, 0]], state_hash="")
    client.ingest_tick_frame(frame0, now_ms=251)

    resume = client.update_pause_state(now_ms=251)
    assert resume is not None
    assert resume.paused is False


def test_client_resend_window_includes_oldest_unconsumed_tick() -> None:
    client = ClientLockstepState(local_slot_index=0, input_delay_ticks=2)
    client._next_consume_tick = 5
    client._capture_tick = 6
    client._sent_inputs[5] = [0.0, 0.0, 0.0, 0.0, 5]
    client._sent_inputs[6] = [0.0, 0.0, 0.0, 0.0, 6]
    client._sent_inputs[7] = [0.0, 0.0, 0.0, 0.0, 7]

    batch = client.queue_local_input([0.0, 0.0, 0.0, 0.0, 1])

    ticks = [sample.tick_index for sample in batch.samples]
    assert 5 in ticks
    assert ticks[0] == 8
