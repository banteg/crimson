from __future__ import annotations

from crimson.net.lockstep import HostLockstepState


def test_host_lockstep_emits_canonical_frames_in_tick_order() -> None:
    host = HostLockstepState(player_count=2)

    host.submit_input_sample(slot_index=1, tick_index=0, packed_input=[1.0, 0.0, [2.0, 3.0], 7])
    host.submit_input_sample(slot_index=0, tick_index=0, packed_input=[-1.0, 0.0, [4.0, 5.0], 3])

    frames = host.pop_ready_frames(
        now_ms=1,
        command_hash_by_tick={0: "cmd0"},
        state_hash_by_tick={0: "state0"},
    )

    assert [frame.tick_index for frame in frames] == [0]
    assert frames[0].frame_inputs[0] == [-1.0, 0.0, [4.0, 5.0], 3]
    assert frames[0].frame_inputs[1] == [1.0, 0.0, [2.0, 3.0], 7]
    assert frames[0].command_hash == "cmd0"
    assert frames[0].state_hash == "state0"


def test_host_lockstep_pauses_and_resumes_on_missing_input() -> None:
    host = HostLockstepState(player_count=2, input_stall_timeout_ms=250)

    host.submit_input_sample(slot_index=0, tick_index=0, packed_input=[0.0, 0.0, [0.0, 0.0], 0])

    pause = host.update_pause_state(now_ms=250)
    assert pause is not None
    assert pause.paused is True
    assert pause.reason == "waiting_input"

    host.submit_input_sample(slot_index=1, tick_index=0, packed_input=[0.0, 0.0, [0.0, 0.0], 0])
    host.pop_ready_frames(now_ms=251)

    resume = host.update_pause_state(now_ms=251)
    assert resume is not None
    assert resume.paused is False
    assert resume.reason == ""
