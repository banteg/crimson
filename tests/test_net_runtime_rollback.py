from __future__ import annotations

from typing import Any

from crimson.net.net_runtime import NetRuntime, NetRuntimeConfig
from crimson.net.relay_protocol import (
    ClientWelcome,
    Ping,
    RbInputBatch,
    RbInputSample,
    RbResyncRequest,
    RoomReady,
    RoomStart,
    RoomState,
)


def _start_runtime(monkeypatch, *, rollback_max_ticks: int = 8) -> tuple[NetRuntime, list[tuple[tuple[str, int], Any]]]:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="ABCD12",
            rollback_max_ticks=int(rollback_max_ticks),
            input_delay_ticks=0,
        )
    )
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(runtime.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
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
    return runtime, sent


def test_runtime_emits_tick_frames_from_local_inputs(monkeypatch) -> None:
    runtime, sent = _start_runtime(monkeypatch)

    runtime.queue_local_input([1.0, 0.0, [0.0, 0.0], 7], now_ms=1001)
    frame = runtime.pop_tick_frame()

    assert frame is not None
    assert frame.tick_index == 0
    assert frame.frame_inputs[0][3] == 7
    assert frame.frame_inputs[1] == [0.0, 0.0, [0.0, 0.0], 0]
    assert any(isinstance(packet.message, RbInputBatch) for _addr, packet in sent)


def test_runtime_tracks_prediction_mismatches_and_rollbacks(monkeypatch) -> None:
    runtime, _sent = _start_runtime(monkeypatch)
    runtime.queue_local_input([0.0, 0.0, [0.0, 0.0], 1], now_ms=1100)
    assert runtime.pop_tick_frame() is not None

    runtime._handle_message(
        message=RbInputBatch(
            slot_index=1,
            samples=[RbInputSample(tick_index=0, packed_input=[1.0, 0.0, [0.0, 0.0], 9])],
        ),
        now_ms=1101,
    )

    assert runtime.rollback_count == 1
    assert runtime.prediction_mismatches == 1
    assert runtime.max_rollback_ticks_seen >= 1
    assert runtime.resync_count == 0


def test_runtime_requests_resync_when_correction_exceeds_rollback_cap(monkeypatch) -> None:
    runtime, sent = _start_runtime(monkeypatch, rollback_max_ticks=2)

    for tick in range(6):
        runtime.queue_local_input([0.0, 0.0, [0.0, 0.0], tick], now_ms=1200 + tick)
        assert runtime.pop_tick_frame() is not None

    runtime._handle_message(
        message=RbInputBatch(
            slot_index=1,
            samples=[RbInputSample(tick_index=2, packed_input=[1.0, 0.0, [0.0, 0.0], 99])],
        ),
        now_ms=1300,
    )

    assert runtime.resync_count == 1
    assert runtime.pop_tick_frame() is None
    assert any(isinstance(packet.message, RbResyncRequest) for _addr, packet in sent)


def test_runtime_prints_host_invite_code_once(monkeypatch) -> None:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
        )
    )
    printed: list[str] = []

    def _capture_print(*args: object, **_kwargs: object) -> None:
        printed.append(" ".join(str(item) for item in args))

    monkeypatch.setattr("builtins.print", _capture_print)

    runtime._handle_message(
        message=RoomState(room_code="AB12", player_count=2),
        now_ms=1000,
    )
    runtime._handle_message(
        message=RoomState(room_code="AB12", player_count=2),
        now_ms=1001,
    )

    assert printed == ["[crimson] Invite code: AB12"]


def test_client_sends_ready_only_after_room_state(monkeypatch) -> None:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="join",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
        )
    )
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(runtime.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._handle_message(
        message=ClientWelcome(accepted=True, peer_id="p1"),
        now_ms=1000,
    )

    runtime.update(now_ms=1000)
    first_wave = [packet.message for _addr, packet in sent]
    assert not any(isinstance(message, RoomReady) for message in first_wave)

    sent.clear()
    runtime._handle_message(message=RoomState(room_code="AB12", player_count=2), now_ms=1100)
    runtime.update(now_ms=1100)
    second_wave = [packet.message for _addr, packet in sent]
    assert any(isinstance(message, RoomReady) for message in second_wave)


def test_host_keeps_lobby_heartbeat_alive(monkeypatch) -> None:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
        )
    )
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(runtime.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._created_room = True
    runtime._joined_room = True
    runtime._sent_ready = True

    runtime.update(now_ms=1000)
    runtime.update(now_ms=1100)
    runtime.update(now_ms=1300)

    messages = [packet.message for _addr, packet in sent]
    assert sum(1 for message in messages if isinstance(message, Ping)) >= 2
