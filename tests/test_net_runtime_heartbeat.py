from __future__ import annotations

from typing import Any

from crimson.net.net_runtime import NetRuntime, NetRuntimeConfig
from crimson.net.relay_protocol import Ping, RoomStart


def _runtime(monkeypatch) -> tuple[NetRuntime, list[tuple[tuple[str, int], Any]]]:
    runtime = NetRuntime(
        NetRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="AB12",
            input_delay_ticks=0,
        ),
    )
    sent: list[tuple[tuple[str, int], Any]] = []
    monkeypatch.setattr(
        type(runtime.transport),
        "send_packet",
        lambda _self, addr, packet: sent.append((addr, packet)),
    )
    monkeypatch.setattr(type(runtime.transport), "recv_packets", lambda _self, **_kwargs: [])
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
    return runtime, sent


def test_continuous_outbound_inputs_still_emit_periodic_pings(monkeypatch) -> None:
    runtime, sent = _runtime(monkeypatch)

    for i in range(20):
        now = 1000 + i * 50
        runtime.queue_local_input([0.0, 0.0, [0.0, 0.0], i], now_ms=now)
        runtime.update(now_ms=now)

    pings = [packet.message for _addr, packet in sent if isinstance(packet.message, Ping)]
    assert len(pings) >= 3


def test_no_false_timeout_before_five_seconds_while_paused(monkeypatch) -> None:
    runtime, _sent = _runtime(monkeypatch)
    runtime._last_seen_ms = 1000
    runtime._paused_for_reconnect = True

    runtime.update(now_ms=5900)

    assert runtime.error == ""
