from __future__ import annotations

import time

from crimson.game_modes import GameMode
from crimson.net.lockstep_protocol import (
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    TICK_RATE,
    Disconnect,
    Hello,
    InputBatch,
    PauseState,
    Ready,
    Welcome,
)
from crimson.net.lockstep_runtime import (
    IDLE_HEARTBEAT_MS,
    PAUSED_LINK_TIMEOUT_MS,
    HostLockstepRuntimeConfig,
    JoinLockstepRuntimeConfig,
    LockstepRuntime,
)
from crimson.net.lockstep_state import HostReadyTick
from crimson.net.reliable import ReliableLink
from crimson.net.transport import UdpTransport
from crimson.persistence.save_status import GameStatusData
from crimson.sim.input_providers import PerkPickCommand


def test_join_hello_retries_keep_reliable_backlog_bounded() -> None:
    start = int(time.monotonic() * 1000.0)
    runtime = LockstepRuntime(
        JoinLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="0.0.0.0",
            host_ip="10.255.255.1",
            port=31993,
        ),
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


def test_host_does_not_track_unknown_non_hello_packets(mocker) -> None:
    runtime = LockstepRuntime(
        HostLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status=GameStatusData(),
        ),
    )
    runtime.open()

    sender = ReliableLink()
    packet = sender.build_packet(Disconnect(reason="x"), reliable=True, now_ms=0)
    addr = ("127.0.0.1", 39999)
    mocker.patch.object(UdpTransport, "recv_packets", return_value=[(addr, packet)])

    runtime.update(now_ms=int(time.monotonic() * 1000.0))

    assert addr not in runtime.host_peers
    lobby = runtime.host_lobby
    assert lobby is not None
    assert addr not in lobby.peers_by_addr
    runtime.close()


def test_host_pop_tick_frame_attaches_pending_commands_to_first_canonical_frame() -> None:
    runtime = LockstepRuntime(
        HostLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status=GameStatusData(),
        ),
    )
    runtime.host_ready_ticks.append(HostReadyTick(tick_index=7, frame_inputs=[[0.0, 0.0, 0.0, 0.0, 0]]))
    runtime.host_ready_ticks.append(HostReadyTick(tick_index=8, frame_inputs=[[1.0, 0.0, 0.0, 0.0, 0]]))
    command = PerkPickCommand(player_index=0, choice_index=2)
    runtime.submit_local_command(command)

    frame0 = runtime.pop_tick_frame()
    frame1 = runtime.pop_tick_frame()

    assert frame0 is not None
    assert frame0.tick_index == 7
    assert frame0.commands == [command]
    assert frame1 is not None
    assert frame1.tick_index == 8
    assert frame1.commands == []


def test_host_timeout_aborts_started_match() -> None:
    runtime = LockstepRuntime(
        HostLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status=GameStatusData(),
        ),
    )
    runtime.open()

    now = int(time.monotonic() * 1000.0)
    addr = ("127.0.0.1", 32001)
    runtime._handle_host_message(
        addr,
        Hello(
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(runtime.build_id),
            mode_id=GameMode.SURVIVAL,
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


def test_host_waiting_input_pause_uses_extended_timeout() -> None:
    runtime = LockstepRuntime(
        HostLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="",
            port=0,
            sim_status=GameStatusData(),
        ),
    )
    runtime.open()

    now = int(time.monotonic() * 1000.0)
    addr = ("127.0.0.1", 32011)
    runtime._handle_host_message(
        addr,
        Hello(
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(runtime.build_id),
            mode_id=GameMode.SURVIVAL,
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

    # Bypass initial loading timeout path and force "paused waiting_input".
    runtime._host_seen_input_slots.add(1)
    lockstep = runtime.host_lockstep
    assert lockstep is not None
    lockstep._paused = True

    check_ms = int(now + 5_000)
    runtime.host_peers[addr].last_seen_ms = int(check_ms - int(LINK_TIMEOUT_MS) - 250)
    runtime.update(now_ms=int(check_ms))
    assert runtime.error == ""
    assert addr in runtime.host_peers

    timeout_ms = int(check_ms + int(PAUSED_LINK_TIMEOUT_MS) + 500)
    runtime.host_peers[addr].last_seen_ms = int(timeout_ms - int(PAUSED_LINK_TIMEOUT_MS) - 1)
    runtime.update(now_ms=int(timeout_ms))
    assert runtime.error == "peer_timeout"
    runtime.close()


def test_client_waiting_input_sends_idle_heartbeat(mocker) -> None:
    runtime = LockstepRuntime(
        JoinLockstepRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            bind_host="127.0.0.1",
            host_ip="127.0.0.1",
            port=31993,
        ),
    )
    runtime.open()
    now = int(time.monotonic() * 1000.0)
    runtime.client_last_seen_ms = int(now)
    runtime.started = True
    runtime.client_pause_state = PauseState(paused=True, reason="waiting_input")
    runtime._client_last_send_ms = int(now - int(IDLE_HEARTBEAT_MS) - 1)

    lobby = runtime.client_lobby
    assert lobby is not None
    lobby.ingest_welcome(Welcome(accepted=True, slot_index=1, session_id="s"))

    send_packet = mocker.patch.object(UdpTransport, "send_packet", autospec=True)

    runtime.update(now_ms=int(now))

    heartbeats = [
        packet
        for packet in [call.args[2] for call in send_packet.call_args_list]
        if isinstance(getattr(packet, "message", None), InputBatch)
        and not bool(getattr(packet, "reliable", False))
        and len(getattr(packet.message, "samples", []) or []) == 0
    ]
    assert heartbeats
    runtime.close()
