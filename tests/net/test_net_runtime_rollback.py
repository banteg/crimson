from __future__ import annotations

import builtins
from unittest.mock import MagicMock

from crimson.net.relay_protocol import (
    ClientWelcome,
    NetMessage,
    Ping,
    RbInputBatch,
    RbInputSample,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
    RbResyncRequest,
    RoomReady,
    RoomStart,
    RoomState,
)
from crimson.net.rollback_resync_v5 import (
    SurvivalRuntimeSnapshotV2,
    SurvivalStateSnapshotV2,
    encode_mode_snapshot,
)
from crimson.net.rollback_runtime import (
    HostRollbackRuntimeConfig,
    JoinRollbackRuntimeConfig,
    RollbackRuntime,
)


def _sent_messages(send_packet: MagicMock) -> list[NetMessage]:
    return [call.args[-1].message for call in send_packet.call_args_list]


def _start_runtime(mocker, *, rollback_max_ticks: int = 8) -> tuple[RollbackRuntime, MagicMock]:
    runtime = RollbackRuntime(
        HostRollbackRuntimeConfig(
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="ABCD12",
            rollback_max_ticks=int(rollback_max_ticks),
            input_delay_ticks=0,
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._handle_message(
        message=RoomStart(
            room_code="ABCD12",
            session_id="s1",
            mode_id=1,
            player_count=2,
            slot_index=0,
            host_slot_index=0,
            input_delay_ticks=0,
            rollback_max_ticks=int(rollback_max_ticks),
            netcode_mode="rollback",
        ),
        now_ms=1000,
    )
    return runtime, send_packet


def test_runtime_emits_tick_frames_from_local_inputs(mocker) -> None:
    runtime, send_packet = _start_runtime(mocker)

    runtime.queue_local_input([1.0, 0.0, 0.0, 0.0, 7], now_ms=1001)
    frame = runtime.pop_tick_frame()

    assert frame is not None
    assert frame.tick_index == 0
    assert frame.frame_inputs[0][4] == 7
    assert frame.frame_inputs[1] == [0.0, 0.0, 0.0, 0.0, 0]
    assert any(isinstance(message, RbInputBatch) for message in _sent_messages(send_packet))


def test_runtime_tracks_prediction_mismatches_and_rollbacks(mocker) -> None:
    runtime, _sent = _start_runtime(mocker)
    runtime.queue_local_input([0.0, 0.0, 0.0, 0.0, 1], now_ms=1100)
    assert runtime.pop_tick_frame() is not None
    runtime.store_local_snapshot(
        0,
        encode_mode_snapshot(
            snapshot=SurvivalStateSnapshotV2(
                tick_index=0,
                runtime_state=SurvivalRuntimeSnapshotV2(
                    sim_elapsed_ms=0.0,
                    stage=0,
                    spawn_cooldown_ms=0.0,
                    perk_pending_count=0,
                ),
            ),
        ),
    )
    runtime.queue_local_input([0.0, 0.0, 0.0, 0.0, 2], now_ms=1101)
    assert runtime.pop_tick_frame() is not None

    runtime._handle_message(
        message=RbInputBatch(
            slot_index=1,
            samples=[RbInputSample(tick_index=1, packed_input=[1.0, 0.0, 0.0, 0.0, 9])],
        ),
        now_ms=1102,
    )

    assert runtime.rollback_count == 1
    assert runtime.prediction_mismatches == 1
    assert runtime.max_rollback_ticks_seen >= 1
    assert runtime.resync_count == 0
    assert runtime.pop_rollback_from() == 1


def test_runtime_requests_resync_when_correction_exceeds_rollback_cap(mocker) -> None:
    runtime, send_packet = _start_runtime(mocker, rollback_max_ticks=2)

    for tick in range(6):
        runtime.queue_local_input([0.0, 0.0, 0.0, 0.0, tick], now_ms=1200 + tick)
        assert runtime.pop_tick_frame() is not None

    runtime._handle_message(
        message=RbInputBatch(
            slot_index=1,
            samples=[RbInputSample(tick_index=2, packed_input=[1.0, 0.0, 0.0, 0.0, 99])],
        ),
        now_ms=1300,
    )

    assert runtime.resync_count == 1
    assert runtime.pop_tick_frame() is None
    assert any(isinstance(message, RbResyncRequest) for message in _sent_messages(send_packet))


def test_runtime_accepts_resync_stream_and_exposes_pending_snapshot(mocker) -> None:
    runtime, _sent = _start_runtime(mocker)
    payload = encode_mode_snapshot(
        snapshot=SurvivalStateSnapshotV2(
            tick_index=12,
            runtime_state=SurvivalRuntimeSnapshotV2(
                sim_elapsed_ms=12.0,
                stage=0,
                spawn_cooldown_ms=0.0,
                perk_pending_count=0,
            ),
        ),
    )

    # Build a valid stream with the real metadata through runtime's host helper.
    host_runtime, host_send_packet = _start_runtime(mocker)
    host_runtime.store_local_snapshot(12, payload)
    host_runtime._handle_message(
        message=RbResyncRequest(request_id="rq1", from_tick=4, reason="overflow", requested_by_slot=1),
        now_ms=1501,
    )
    sent_packets = _sent_messages(host_send_packet)
    begin = next(message for message in sent_packets if isinstance(message, RbResyncBegin))
    chunks = [message for message in sent_packets if isinstance(message, RbResyncChunk)]
    commit = next(message for message in sent_packets if isinstance(message, RbResyncCommit))

    runtime._handle_message(message=begin, now_ms=1502)
    for chunk in chunks:
        runtime._handle_message(message=chunk, now_ms=1503)
    runtime._handle_message(message=commit, now_ms=1504)

    snapshot = runtime.pop_resync_snapshot()
    assert snapshot is not None
    assert snapshot[0] == 12
    runtime.mark_resync_applied(snapshot[0])


def test_runtime_prints_host_invite_code_once(mocker) -> None:
    runtime = RollbackRuntime(
        HostRollbackRuntimeConfig(
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
        ),
    )
    print_mock = mocker.patch.object(builtins, "print")

    runtime._handle_message(
        message=RoomState(room_code="AB12", player_count=2),
        now_ms=1000,
    )
    runtime._handle_message(
        message=RoomState(room_code="AB12", player_count=2),
        now_ms=1001,
    )

    print_mock.assert_called_once_with("[crimson] Invite code: AB12", flush=True)


def test_client_sends_ready_only_after_room_state(mocker) -> None:
    runtime = RollbackRuntime(
        JoinRollbackRuntimeConfig(
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._handle_message(
        message=ClientWelcome(accepted=True, peer_id="p1"),
        now_ms=1000,
    )

    runtime.update(now_ms=1000)
    first_wave = _sent_messages(send_packet)
    assert not any(isinstance(message, RoomReady) for message in first_wave)

    send_packet.reset_mock()
    runtime._handle_message(message=RoomState(room_code="AB12", player_count=2), now_ms=1100)
    runtime.update(now_ms=1100)
    second_wave = _sent_messages(send_packet)
    assert any(isinstance(message, RoomReady) for message in second_wave)


def test_host_keeps_lobby_heartbeat_alive(mocker) -> None:
    runtime = RollbackRuntime(
        HostRollbackRuntimeConfig(
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._created_room = True
    runtime._joined_room = True
    runtime._sent_ready = True

    runtime.update(now_ms=1000)
    runtime.update(now_ms=1100)
    runtime.update(now_ms=1300)

    messages = _sent_messages(send_packet)
    assert sum(1 for message in messages if isinstance(message, Ping)) >= 2
