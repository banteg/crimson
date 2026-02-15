from __future__ import annotations

import time

from crimson.net.protocol import (
    Disconnect,
    Hello,
    INPUT_DELAY_TICKS,
    PROTOCOL_VERSION,
    Ready,
    StatusSnapshot,
    TICK_RATE,
)
from crimson.net.reliable import ReliableLink
from crimson.net.runtime import LanRuntime, LanRuntimeConfig
from crimson.net.transport import UdpTransport


def test_join_hello_retries_keep_reliable_backlog_bounded() -> None:
    start = int(time.monotonic() * 1000.0)
    runtime = LanRuntime(
        LanRuntimeConfig(
            role="join",
            mode_id=1,
            player_count=2,
            bind_host="0.0.0.0",
            host_ip="10.255.255.1",
            port=31993,
        )
    )
    runtime.open()

    now = int(start)
    for _ in range(240):
        runtime.update(now_ms=int(now))
        now += 16

    link = runtime.client_link
    assert link is not None
    assert int(link.pending_count) <= 1
    assert runtime.error in {"", "timeout"}
    runtime.close()


def test_host_does_not_track_unknown_non_hello_packets(monkeypatch) -> None:
    runtime = LanRuntime(
        LanRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status_snapshot=StatusSnapshot(),
        )
    )
    runtime.open()

    sender = ReliableLink()
    packet = sender.build_packet(Disconnect(reason="x"), reliable=True, now_ms=0)
    addr = ("127.0.0.1", 39999)
    monkeypatch.setattr(UdpTransport, "recv_packets", lambda _self, **_kwargs: [(addr, packet)])

    runtime.update(now_ms=int(time.monotonic() * 1000.0))

    assert addr not in runtime.host_peers
    lobby = runtime.host_lobby
    assert lobby is not None
    assert addr not in lobby.peers_by_addr
    runtime.close()


def test_host_timeout_aborts_started_match() -> None:
    runtime = LanRuntime(
        LanRuntimeConfig(
            role="host",
            mode_id=1,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status_snapshot=StatusSnapshot(),
        )
    )
    runtime.open()

    now = int(time.monotonic() * 1000.0)
    addr = ("127.0.0.1", 32001)
    runtime._handle_host_message(
        addr,
        Hello(
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(runtime.build_id),
            mode_id=1,
            player_count=2,
            tick_rate=int(TICK_RATE),
            input_delay_ticks=int(INPUT_DELAY_TICKS),
            host=False,
        ),
        now_ms=int(now),
    )
    lobby = runtime.host_lobby
    assert lobby is not None
    slot = lobby.slot_for_addr(addr)
    assert slot == 1
    lobby.process_ready(addr, Ready(slot_index=int(slot), ready=True))
    runtime.update(now_ms=int(now + 1))
    assert runtime.started is True
    assert addr in runtime.host_peers

    runtime.host_peers[addr].last_seen_ms = int(now - 20_000)
    runtime.update(now_ms=int(now + 20_001))

    assert runtime.error == "peer_timeout"
    runtime.close()
