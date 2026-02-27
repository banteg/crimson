from __future__ import annotations

from unittest.mock import MagicMock

from crimson.net.net_runtime import NetRuntime, NetRuntimeConfig
from crimson.net.relay_protocol import (
    ClientHello,
    ClientWelcome,
    PeerDisconnect,
    RelaySlot,
    RoomJoin,
    RoomStart,
    RoomState,
)


def _sent_messages(send_packet: MagicMock) -> list[object]:
    return [call.args[-1].message for call in send_packet.call_args_list]


def _started_runtime(mocker) -> tuple[NetRuntime, MagicMock]:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="ABCD12",
            input_delay_ticks=0,
            reconnect_timeout_ms=500,
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    mocker.patch.object(type(runtime.transport), "recv_packets", return_value=[])
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._joined_room = True
    runtime._handle_message(
        message=RoomStart(
            room_code="ABCD12",
            session_id="s1",
            mode_id=1,
            player_count=2,
            slot_index=0,
            host_slot_index=0,
            input_delay_ticks=0,
            rollback_max_ticks=8,
            netcode_mode="rollback",
            reconnect_token="tok123",
        ),
        now_ms=1000,
    )
    return runtime, send_packet


def test_peer_disconnect_pauses_and_timeout_aborts(mocker) -> None:
    runtime, _sent = _started_runtime(mocker)

    runtime._handle_message(message=PeerDisconnect(slot_index=1, reason="timeout"), now_ms=1200)
    assert runtime.reconnect_count == 1
    assert runtime.pop_tick_frame() is None

    runtime.update(now_ms=1701)
    assert runtime.error == "reconnect_timeout"


def test_reconnect_room_state_clears_pause_and_resumes(mocker) -> None:
    runtime, _sent = _started_runtime(mocker)

    runtime._handle_message(message=PeerDisconnect(slot_index=1, reason="network_drop"), now_ms=2200)
    assert runtime.pop_tick_frame() is None

    runtime._handle_message(
        message=RoomState(
            room_code="ABCD12",
            session_id="s1",
            mode_id=1,
            player_count=2,
            input_delay_ticks=0,
            rollback_max_ticks=8,
            netcode_mode="rollback",
            slots=[
                RelaySlot(slot_index=0, connected=True, ready=True, is_host=True, peer_name=""),
                RelaySlot(slot_index=1, connected=True, ready=True, is_host=False, peer_name=""),
            ],
            all_ready=True,
            started=True,
        ),
        now_ms=2201,
    )

    runtime.queue_local_input([1.0, 0.0, 0.0, 0.0, 1], now_ms=2202)
    frame = runtime.pop_tick_frame()
    assert frame is not None
    assert runtime.error == ""


def test_link_timeout_starts_self_reconnect_join_with_token(mocker) -> None:
    runtime, send_packet = _started_runtime(mocker)
    runtime._last_seen_ms = 1000

    runtime.update(now_ms=6201)
    assert runtime._reconnect_state == "self_reconnecting"

    runtime.update(now_ms=6202)
    messages = _sent_messages(send_packet)
    assert any(isinstance(message, ClientHello) for message in messages)

    send_packet.reset_mock()
    runtime._handle_message(message=ClientWelcome(accepted=True, peer_id="p1"), now_ms=6203)
    runtime.update(now_ms=6204)
    join_messages = _sent_messages(send_packet)
    assert any(isinstance(message, RoomJoin) and message.reconnect_token == "tok123" for message in join_messages)
