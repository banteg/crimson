from __future__ import annotations

from unittest.mock import MagicMock

from crimson.net.relay_protocol import Ping, RoomStart
from crimson.net.rollback_runtime import HostRollbackRuntimeConfig, RollbackRuntime


def _runtime(mocker) -> tuple[RollbackRuntime, MagicMock]:
    runtime = RollbackRuntime(
        HostRollbackRuntimeConfig(
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
            input_delay_ticks=0,
        ),
    )
    send_packet = mocker.patch.object(type(runtime.transport), "send_packet")
    mocker.patch.object(type(runtime.transport), "recv_packets", return_value=[])
    runtime._server_addr = ("127.0.0.1", 31993)
    runtime._accepted = True
    runtime._joined_room = True
    runtime._sent_ready = True
    runtime._handle_message(
        message=RoomStart(
            room_code="AB12",
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


def test_continuous_outbound_inputs_still_emit_periodic_pings(mocker) -> None:
    runtime, send_packet = _runtime(mocker)

    for i in range(20):
        now = 1000 + i * 50
        runtime.queue_local_input([0.0, 0.0, 0.0, 0.0, i], now_ms=now)
        runtime.update(now_ms=now)

    pings = [call.args[-1].message for call in send_packet.call_args_list if isinstance(call.args[-1].message, Ping)]
    assert len(pings) >= 3


def test_no_false_timeout_before_five_seconds_while_paused(mocker) -> None:
    runtime, _sent = _runtime(mocker)
    runtime._last_seen_ms = 1000
    runtime._paused_for_reconnect = True

    runtime.update(now_ms=5900)

    assert runtime.error == ""
