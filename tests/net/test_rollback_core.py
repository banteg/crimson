from __future__ import annotations

from crimson.net.relay_protocol import RbInputSample
from crimson.net.rollback import RollbackController


def test_prediction_uses_hold_last_or_neutral_for_missing_remote_inputs() -> None:
    controller = RollbackController(player_count=2, local_slot_index=0, input_delay_ticks=0, max_rollback_ticks=8)

    controller.queue_local_input([1.0, 0.0, 0.0, 0.0, 1])
    frame0 = controller.pop_frame()

    assert frame0 is not None
    assert frame0.tick_index == 0
    assert frame0.predicted_slots == (1,)
    assert frame0.frame_inputs[0][4] == 1
    assert frame0.frame_inputs[1] == [0.0, 0.0, 0.0, 0.0, 0]


def test_prediction_mismatch_requests_rollback_within_cap() -> None:
    controller = RollbackController(player_count=2, local_slot_index=0, input_delay_ticks=0, max_rollback_ticks=8)

    controller.queue_local_input([0.0, 0.0, 0.0, 0.0, 1])
    assert controller.pop_frame() is not None

    controller.ingest_remote_samples(
        slot_index=1,
        samples=[
            # Late correction for a previously predicted tick.
            RbInputSample(tick_index=0, packed_input=[1.0, 0.0, 0.0, 0.0, 9]),
        ],
    )

    assert controller.drain_rollback_from() == 0
    assert controller.drain_resync_from() is None
    assert controller.rollback_count == 1
    assert controller.prediction_mismatches == 1


def test_noop_correction_does_not_trigger_rollback() -> None:
    controller = RollbackController(player_count=2, local_slot_index=0, input_delay_ticks=0, max_rollback_ticks=8)

    controller.queue_local_input([0.0, 0.0, 0.0, 0.0, 1])
    assert controller.pop_frame() is not None

    controller.ingest_remote_samples(
        slot_index=1,
        samples=[
            RbInputSample(tick_index=0, packed_input=[0.0, 0.0, 0.0, 0.0, 0]),
        ],
    )

    assert controller.drain_rollback_from() is None
    assert controller.drain_resync_from() is None
    assert controller.rollback_count == 0
    assert controller.prediction_mismatches == 0


def test_corrections_older_than_cap_trigger_resync_request() -> None:
    controller = RollbackController(player_count=2, local_slot_index=0, input_delay_ticks=0, max_rollback_ticks=2)

    for tick in range(6):
        controller.queue_local_input([0.0, 0.0, 0.0, 0.0, tick])
        assert controller.pop_frame() is not None

    controller.ingest_remote_samples(
        slot_index=1,
        samples=[
            # Use tick 2 so the emitted-frame history still tracks this frame.
            RbInputSample(tick_index=2, packed_input=[1.0, 0.0, 0.0, 0.0, 99]),
        ],
    )

    assert controller.drain_rollback_from() is None
    assert controller.drain_resync_from() == 2
    assert controller.rollback_count == 0
    assert controller.prediction_mismatches == 1
