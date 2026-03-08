from __future__ import annotations

import datetime as dt
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeAlias

import msgspec

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from ..replay.types import PackedPlayerInput
from ..sim.input_providers import GameCommand
from ..sim.timing import ftol_ms_i32
from .debug_log import lan_debug_log, lan_debug_log_path, set_lan_debug_forwarder
from .lockstep_lobby import ClientLobby, HostLobby
from .lockstep_protocol import (
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    TICK_RATE,
    DebugLogBatch,
    Disconnect,
    Hello,
    InputBatch,
    KeepAlive,
    LobbyState,
    MatchStart,
    NetMessage,
    PauseState,
    Ready,
    StatusSnapshot,
    TickFrame,
    Welcome,
    current_build_id,
)
from .lockstep_state import ClientLockstepState, HostLockstepState, HostReadyTick
from .reliable import ReliableLink
from .session_settings import (
    hello_from_session_settings,
    session_settings_for_lockstep,
    session_settings_from_hello,
    session_settings_from_match_start,
    session_settings_from_welcome,
)
from .transport import PeerAddr, UdpTransport


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


# The host is authoritative and doesn't need to queue inputs far ahead. Keeping
# the host capture clock close to lockstep progress avoids persistent host-side
# input lag if the host stalls briefly and then "runs behind" real time.
HOST_MAX_CAPTURE_LEAD_TICKS = 1

# Best-effort debug log mirroring from clients to host.
CLIENT_LOG_FORWARD_FLUSH_MS = 200
CLIENT_LOG_FORWARD_MAX_QUEUE_LINES = 5000
CLIENT_LOG_FORWARD_MAX_LINES_PER_BATCH = 50
# Keep under common MTU to avoid fragmentation (msgpack overhead not accounted).
CLIENT_LOG_FORWARD_MAX_CHARS_PER_BATCH = 900

# `LINK_TIMEOUT_MS` is tuned for responsive LAN failure detection, but gameplay
# view transitions can include multi-second stalls (e.g. terrain generation).
# Use a more forgiving timeout until lockstep traffic is flowing.
LOADING_LINK_TIMEOUT_MS = 10_000
KEEPALIVE_INTERVAL_MS = 250

# During intentional gameplay pauses (e.g. perk selection) peers can stop
# producing fresh inputs for longer than the normal 1s failure timeout.
PAUSED_LINK_TIMEOUT_MS = 60_000

# Bound socket drain work per update to avoid frame-time spikes under burst traffic.
MAX_RECV_PACKETS_PER_UPDATE = 512

# When gameplay is paused and no new inputs are generated, periodically send a
# tiny no-op batch so ACK progression and timeout tracking stay alive.
IDLE_HEARTBEAT_MS = 250


class _LockstepRuntimeConfigBase(msgspec.Struct):
    mode_id: GameMode
    player_count: int
    bind_host: str
    host_ip: str
    port: int
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: int = TICK_RATE
    input_delay_ticks: int = INPUT_DELAY_TICKS
    sim_status_snapshot: StatusSnapshot | None = None


class HostLockstepRuntimeConfig(_LockstepRuntimeConfigBase):
    role: Literal["host"] = "host"


class JoinLockstepRuntimeConfig(_LockstepRuntimeConfigBase):
    role: Literal["join"] = "join"


LockstepRuntimeConfig: TypeAlias = HostLockstepRuntimeConfig | JoinLockstepRuntimeConfig


class _HostPeerLink(msgspec.Struct):
    addr: PeerAddr
    link: ReliableLink = msgspec.field(default_factory=ReliableLink)
    last_seen_ms: int = 0


def _reset_desync_counters(runtime: object) -> None:
    runtime.desync_count = 0  # type: ignore[attr-defined]
    runtime.last_desync_tick = -1  # type: ignore[attr-defined]
    runtime.last_desync_kind = ""  # type: ignore[attr-defined]
    runtime.last_desync_expected = ""  # type: ignore[attr-defined]
    runtime.last_desync_actual = ""  # type: ignore[attr-defined]


def _note_desync(*, role: str, runtime: object, kind: str, tick_index: int, expected: str, actual: str) -> None:
    runtime.desync_count = int(runtime.desync_count) + 1  # type: ignore[attr-defined]
    runtime.last_desync_tick = int(tick_index)  # type: ignore[attr-defined]
    runtime.last_desync_kind = str(kind)  # type: ignore[attr-defined]
    runtime.last_desync_expected = str(expected)  # type: ignore[attr-defined]
    runtime.last_desync_actual = str(actual)  # type: ignore[attr-defined]
    lan_debug_log(
        "lan_desync",
        role=str(role),
        kind=str(kind),
        tick_index=int(tick_index),
        expected=str(expected),
        actual=str(actual),
    )


@dataclass(slots=True)
class HostLockstepRuntime:
    """Host-side LAN lobby handshake and lockstep driver."""

    cfg: HostLockstepRuntimeConfig
    build_id: str = field(default_factory=current_build_id)
    transport: UdpTransport = field(init=False)
    started: bool = False
    error: str = ""

    lobby: HostLobby | None = None
    peers: dict[PeerAddr, _HostPeerLink] = field(default_factory=dict)
    seed: int = 0
    match_start_event: MatchStart | None = None
    last_broadcast_ms: int = 0
    lockstep: HostLockstepState | None = None
    capture_tick: int = 0
    ready_ticks: deque[HostReadyTick] = field(default_factory=deque)
    _pending_commands: list[GameCommand] = field(default_factory=list)
    _seen_input_slots: set[int] = field(default_factory=set)

    _metrics_last_log_ms: int = 0
    _metrics_last_resends_total: int = 0
    _input_queued_at_ms: dict[int, int] = field(default_factory=dict)
    local_input_latency_ms: int = 0
    local_input_latency_ewma_ms: float = 0.0

    desync_count: int = 0
    last_desync_tick: int = -1
    last_desync_kind: str = ""
    last_desync_expected: str = ""
    last_desync_actual: str = ""

    _remote_log_paths: dict[int, Path] = field(default_factory=dict)
    _neutral_input: PackedPlayerInput = field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0, 0])
    _last_send_ms: int = 0

    def __post_init__(self) -> None:
        self.transport = UdpTransport(bind_host=str(self.cfg.bind_host), bind_port=int(self.cfg.port))

    def open(self) -> None:
        if self.lobby is not None:
            return
        self.transport.open()
        self.started = False
        self.error = ""
        self._last_send_ms = 0
        self._metrics_last_log_ms = 0
        self._metrics_last_resends_total = 0
        self._input_queued_at_ms.clear()
        self.local_input_latency_ms = 0
        self.local_input_latency_ewma_ms = 0.0
        self._seen_input_slots.clear()
        _reset_desync_counters(self)
        self._remote_log_paths.clear()
        lan_debug_log(
            "net_open",
            role="host",
            bind_host=str(self.cfg.bind_host),
            bind_port=int(self.transport.bound_port),
            build_id=str(self.build_id),
            mode_id=int(self.cfg.mode_id),
            player_count=int(self.cfg.player_count),
            tick_rate=int(self.cfg.tick_rate),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.lobby = HostLobby(
            mode_id=self.cfg.mode_id,
            player_count=int(self.cfg.player_count),
            build_id=str(self.build_id),
            tick_rate=int(self.cfg.tick_rate),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
            quest_level=self.cfg.quest_level,
            preserve_bugs=bool(self.cfg.preserve_bugs),
        )
        self.last_broadcast_ms = _now_ms()

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.lobby = None
            self.peers.clear()
            self.seed = 0
            self.match_start_event = None
            self.last_broadcast_ms = 0
            self.lockstep = None
            self.capture_tick = 0
            self.ready_ticks.clear()
            self._pending_commands.clear()
            self._last_send_ms = 0
            self._metrics_last_log_ms = 0
            self._metrics_last_resends_total = 0
            self._input_queued_at_ms.clear()
            self.local_input_latency_ms = 0
            self.local_input_latency_ewma_ms = 0.0
            self._seen_input_slots.clear()
            _reset_desync_counters(self)
            self._remote_log_paths.clear()
            self.started = False
            self.error = ""
            lan_debug_log("net_close", role="host")

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    @property
    def local_slot_index(self) -> int:
        return 0

    def debug_overlay_lines(self) -> list[str]:
        lines: list[str] = []
        now_ms = _now_ms()
        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = ftol_ms_i32(float(delay_ticks) * 1000.0 / float(tick_rate))

        if self.error:
            lines.append(f"net: error={self.error}")
        if int(self.desync_count) > 0:
            exp = str(self.last_desync_expected or "")[:8]
            act = str(self.last_desync_actual or "")[:8]
            lines.append(
                "desyncs: "
                f"{int(self.desync_count)} "
                f"last={str(self.last_desync_kind or '?')}@{int(self.last_desync_tick)} "
                f"{exp}!={act}",
            )

        peer_total = max(0, int(self.cfg.player_count) - 1)
        emit_tick = 0
        lead_ticks = 0
        waiting_for = 0
        stall_ms = 0
        if self.lockstep is not None:
            emit_tick = int(self.lockstep.next_emit_tick)
            lead_ticks = int(self.capture_tick) - int(emit_tick)
            waiting_for = int(self.lockstep.waiting_for_inputs())
            if waiting_for > 0:
                stall_ms = max(0, int(now_ms) - int(self.lockstep.last_progress_ms))
        rtts = [int(peer.link.rtt_last_ms) for peer in self.peers.values() if peer.link.rtt_last_ms > 0]
        rtt_label = "?"
        if rtts:
            rtt_label = f"{min(rtts)}..{max(rtts)}"
        pending_max = max((int(peer.link.pending_count) for peer in self.peers.values()), default=0)
        lines.append(
            "net(host): "
            f"peers={len(self.peers)}/{int(peer_total)} "
            f"emit={int(emit_tick)} "
            f"lead={int(lead_ticks)} "
            f"wait={int(waiting_for)} "
            f"stall={int(stall_ms)}ms",
        )
        lines.append(
            "link(host): "
            f"delay={delay_ticks}t({delay_ms}ms) "
            f"rtt={rtt_label}ms "
            f"pending={int(pending_max)}",
        )
        return lines

    def lobby_state(self) -> LobbyState | None:
        if self.lobby is None:
            return None
        return self.lobby.lobby_state()

    def match_start(self) -> MatchStart | None:
        return self.match_start_event

    def note_desync(self, *, kind: str, tick_index: int, expected: str, actual: str) -> None:
        _note_desync(role="host", runtime=self, kind=kind, tick_index=tick_index, expected=expected, actual=actual)

    def host_remote_inputs_ready(self) -> bool:
        if self.lockstep is None:
            return False
        player_count = max(1, int(self.lockstep.player_count))
        for slot in range(1, int(player_count)):
            if int(slot) not in self._seen_input_slots:
                return False
        return True

    def queue_local_input(self, packed_input: PackedPlayerInput, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        if self.lockstep is None:
            return
        max_capture_tick = int(self.lockstep.next_emit_tick) + int(HOST_MAX_CAPTURE_LEAD_TICKS)
        if int(self.capture_tick) > int(max_capture_tick):
            self.capture_tick = int(max_capture_tick)
        target_tick = int(self.capture_tick) + int(self.cfg.input_delay_ticks)
        self._input_queued_at_ms[int(target_tick)] = int(now_ms)
        self.lockstep.submit_input_sample(
            slot_index=0,
            tick_index=int(target_tick),
            packed_input=list(packed_input),
        )
        self.capture_tick += 1

    def pop_tick_frame(self) -> TickFrame | None:
        if not self.ready_ticks:
            return None
        ready = self.ready_ticks.popleft()
        commands = list(self._pending_commands)
        self._pending_commands.clear()
        return TickFrame(
            tick_index=int(ready.tick_index),
            frame_inputs=[list(packed) for packed in ready.frame_inputs],
            commands=commands,
        )

    def submit_local_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)

    def broadcast_tick_frame(self, frame: TickFrame, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        self._broadcast(frame, reliable=True, now_ms=int(now_ms))

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        self._update(now_ms=int(now_ms))
        self._trace_metrics(now_ms=int(now_ms))

    def _abort_match(self, *, reason: str, now_ms: int, addr: PeerAddr | None = None) -> None:
        if not bool(self.started) or self.error:
            return
        self.error = str(reason)
        details: dict[str, object] = {"role": "host", "reason": str(reason)}
        if addr is not None:
            details["addr"] = f"{addr[0]}:{int(addr[1])}"
        lan_debug_log("net_match_abort", **details)
        self._broadcast(Disconnect(reason=str(reason)), reliable=True, now_ms=int(now_ms))

    def _write_remote_log_batch(self, *, addr: PeerAddr, slot_index: int, lines: list[str]) -> None:
        if int(slot_index) <= 0 or not lines:
            return

        path = self._remote_log_paths.get(int(slot_index))
        if path is None:
            host_path = lan_debug_log_path()
            if host_path is None:
                return
            safe_ip = str(addr[0]).replace(":", "_").replace("/", "_")
            timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            path = host_path.parent / f"lan-client-slot{int(slot_index)}-from{safe_ip}-{int(addr[1])}-{timestamp}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            session_id = ""
            if self.lobby is not None:
                session_id = str(self.lobby.session_id)
            init_ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
            init_line = (
                f"{init_ts} event=remote_log_init slot_index={int(slot_index)} "
                f"addr={addr[0]}:{int(addr[1])} session_id={session_id}\n"
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(init_line)
            self._remote_log_paths[int(slot_index)] = path

        with path.open("a", encoding="utf-8") as handle:
            for line in lines:
                text = str(line)
                if not text.endswith("\n"):
                    text += "\n"
                handle.write(text)

    def _update(self, *, now_ms: int) -> None:
        lobby = self.lobby
        if lobby is None:
            return

        for addr, packet in self.transport.recv_packets(max_packets=int(MAX_RECV_PACKETS_PER_UPDATE)):
            peer_link = self.peers.get(addr)
            if peer_link is None:
                message = packet.message
                if isinstance(message, Hello):
                    self._handle_message(addr, message, now_ms=int(now_ms))
                    accepted_peer = self.peers.get(addr)
                    if accepted_peer is not None and bool(packet.reliable) and int(packet.seq) > 0:
                        accepted_peer.link.prime_recv_seq(int(packet.seq))
                continue
            peer_link.last_seen_ms = int(now_ms)
            messages, dup = peer_link.link.ingest_packet(packet, now_ms=int(now_ms))
            if dup:
                lan_debug_log("net_recv_dup", role="host", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_message(addr, message, now_ms=int(now_ms))

        timeout_ms = int(LINK_TIMEOUT_MS)
        if bool(lobby.started) and (not bool(self.host_remote_inputs_ready())):
            timeout_ms = int(LOADING_LINK_TIMEOUT_MS)
        if bool(lobby.started) and self.lockstep is not None and bool(self.lockstep.paused):
            timeout_ms = max(int(timeout_ms), int(PAUSED_LINK_TIMEOUT_MS))
        for addr, peer in list(self.peers.items()):
            if (int(now_ms) - int(peer.last_seen_ms)) < int(timeout_ms):
                continue
            slot = lobby.slot_for_addr(addr)
            self.peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            if slot is not None:
                self._seen_input_slots.discard(int(slot))
            lan_debug_log(
                "net_timeout",
                role="host",
                addr=f"{addr[0]}:{addr[1]}",
                timeout_ms=int(timeout_ms),
                started=bool(lobby.started),
            )
            if bool(lobby.started):
                self._abort_match(reason="peer_timeout", now_ms=int(now_ms), addr=addr)

        if (not lobby.started) and (int(now_ms) - int(self.last_broadcast_ms)) >= 250:
            self.last_broadcast_ms = int(now_ms)
            self._broadcast_lobby_state(now_ms=int(now_ms))

        if (not lobby.started) and lobby.all_ready():
            status_snapshot = self.cfg.sim_status_snapshot
            if status_snapshot is None:
                self.error = "missing_sim_status_snapshot"
                lan_debug_log("net_sanity_error", role="host", kind="match_start", reason=str(self.error))
                return
            self.seed = int((_now_ms() * 1103515245 + 12345) & 0xFFFFFFFF)
            event = lobby.start_match(seed=int(self.seed), status_snapshot=status_snapshot)
            self.started = True
            self.match_start_event = event
            self._init_lockstep(event)
            self._seen_input_slots.clear()
            lan_debug_log(
                "net_match_start",
                role="host",
                session_id=str(event.session_id or ""),
                mode_id=int(event.mode_id),
                player_count=int(event.player_count),
                seed=int(event.seed),
                start_tick=int(event.start_tick),
                quest_level=str(event.quest_level or ""),
                preserve_bugs=bool(event.preserve_bugs),
                status_quest_unlock_index=int(status_snapshot.quest_unlock_index),
                status_quest_unlock_index_full=int(status_snapshot.quest_unlock_index_full),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
            )
            self._broadcast(event, reliable=True, now_ms=int(now_ms))

        if self.lockstep is not None:
            pause = self.lockstep.update_pause_state(now_ms=int(now_ms))
            if pause is not None:
                self._broadcast(pause, reliable=True, now_ms=int(now_ms))
            frames = self.lockstep.pop_ready_frames(now_ms=int(now_ms))
            for frame in frames:
                tick = int(frame.tick_index)
                queued_at = self._input_queued_at_ms.pop(int(tick), None)
                if queued_at is not None:
                    latency_ms = max(0, int(now_ms) - int(queued_at))
                    self.local_input_latency_ms = int(latency_ms)
                    if self.local_input_latency_ewma_ms <= 0.0:
                        self.local_input_latency_ewma_ms = float(latency_ms)
                    else:
                        self.local_input_latency_ewma_ms = float(
                            self.local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1,
                        )
                self.ready_ticks.append(frame)

        for addr, peer in self.peers.items():
            for resend in peer.link.poll_resends(now_ms=int(now_ms)):
                try:
                    self.transport.send_packet(addr, resend)
                except OSError:
                    continue
                self._last_send_ms = int(now_ms)

        if bool(self.started) and self.peers:
            last_send = int(self._last_send_ms)
            if last_send <= 0:
                self._last_send_ms = int(now_ms)
            elif (int(now_ms) - int(last_send)) >= int(KEEPALIVE_INTERVAL_MS):
                tick_index = 0
                if self.lockstep is not None:
                    tick_index = int(self.lockstep.next_emit_tick)
                self._broadcast(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

    def _handle_message(self, addr: PeerAddr, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.lobby
        if lobby is None:
            return
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, Hello):
            lan_debug_log(
                "net_recv",
                role="host",
                kind="hello",
                addr=f"{addr[0]}:{addr[1]}",
                protocol_version=int(message.protocol_version),
                build_id=str(message.build_id or ""),
                mode_id=int(message.mode_id),
                player_count=int(message.player_count),
                tick_rate=int(message.tick_rate),
                input_delay_ticks=int(message.input_delay_ticks),
                quest_level=str(message.quest_level or ""),
                preserve_bugs=bool(message.preserve_bugs),
                host=bool(message.host),
            )
            welcome = lobby.process_hello(addr, message)
            lan_debug_log(
                "lobby_welcome",
                role="host",
                addr=f"{addr[0]}:{addr[1]}",
                accepted=bool(welcome.accepted),
                reason=str(welcome.reason or ""),
                slot_index=int(welcome.slot_index),
                session_id=str(welcome.session_id),
            )
            if bool(welcome.accepted):
                peer = self.peers.get(addr)
                if peer is None:
                    self.peers[addr] = _HostPeerLink(addr=addr, last_seen_ms=int(now_ms))
                else:
                    peer.last_seen_ms = int(now_ms)
            self._send(addr, welcome, reliable=True, now_ms=int(now_ms), track_peer=bool(welcome.accepted))
            self._broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, Ready):
            lan_debug_log(
                "net_recv",
                role="host",
                kind="ready",
                addr=f"{addr[0]}:{addr[1]}",
                slot_index=int(message.slot_index),
                ready=bool(message.ready),
            )
            lobby.process_ready(addr, message)
            self._broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, Disconnect):
            lan_debug_log("net_recv", role="host", kind="disconnect", addr=f"{addr[0]}:{addr[1]}")
            slot = lobby.slot_for_addr(addr)
            self.peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            if slot is not None:
                self._seen_input_slots.discard(int(slot))
            if bool(lobby.started):
                self._abort_match(reason="peer_disconnect", now_ms=int(now_ms), addr=addr)
            self._broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, DebugLogBatch):
            mapped_slot = lobby.slot_for_addr(addr)
            msg_slot = int(message.slot_index)
            slot_index = int(mapped_slot) if mapped_slot is not None else int(msg_slot)
            if int(slot_index) <= 0:
                return
            self._write_remote_log_batch(addr=addr, slot_index=int(slot_index), lines=list(message.lines))
            return
        if isinstance(message, InputBatch):
            if self.lockstep is None:
                return
            mapped_slot = lobby.slot_for_addr(addr)
            if mapped_slot is None:
                return
            if int(mapped_slot) > 0:
                self._seen_input_slots.add(int(mapped_slot))
            batch = message
            if int(batch.slot_index) != int(mapped_slot):
                batch = InputBatch(slot_index=int(mapped_slot), samples=list(batch.samples))
            max_tick = -1
            min_tick = 2**31 - 1
            for sample in batch.samples:
                tick = int(sample.tick_index)
                max_tick = max(int(max_tick), int(tick))
                min_tick = min(int(min_tick), int(tick))
            if max_tick >= 0 and (int(max_tick) < 5 or (int(max_tick) % 60) == 0):
                lan_debug_log(
                    "net_recv",
                    role="host",
                    kind="input_batch",
                    addr=f"{addr[0]}:{addr[1]}",
                    slot_index=int(batch.slot_index),
                    sample_count=len(batch.samples),
                    tick_min=int(min_tick) if min_tick != 2**31 - 1 else 0,
                    tick_max=int(max_tick),
                )
            self.lockstep.submit_input_batch(batch)

    def _send(
        self,
        addr: PeerAddr,
        message: NetMessage,
        *,
        reliable: bool,
        now_ms: int,
        track_peer: bool = True,
    ) -> None:
        peer = self.peers.get(addr)
        if peer is None and bool(track_peer):
            peer = _HostPeerLink(addr=addr, last_seen_ms=int(now_ms))
            self.peers[addr] = peer
        if peer is not None:
            packet = peer.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        else:
            packet = ReliableLink().build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(addr, packet)
        except OSError:
            return
        self._last_send_ms = int(now_ms)
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, TickFrame):
            tick = int(message.tick_index)
            if int(tick) < 5 or (int(tick) % 60) == 0:
                lan_debug_log(
                    "net_send",
                    role="host",
                    kind="tick_frame",
                    addr=f"{addr[0]}:{addr[1]}",
                    reliable=bool(reliable),
                    tick_index=int(tick),
                    command_count=len(message.commands),
                )
            return
        if isinstance(message, PauseState):
            lan_debug_log(
                "net_send",
                role="host",
                kind="pause_state",
                addr=f"{addr[0]}:{addr[1]}",
                reliable=bool(reliable),
                paused=bool(message.paused),
                reason=str(message.reason or ""),
            )
            return
        lan_debug_log(
            "net_send",
            role="host",
            kind=type(message).__name__,
            addr=f"{addr[0]}:{addr[1]}",
            reliable=bool(reliable),
        )

    def _broadcast(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        for addr in list(self.peers):
            self._send(addr, message, reliable=bool(reliable), now_ms=int(now_ms))

    def _broadcast_lobby_state(self, *, now_ms: int) -> None:
        if self.lobby is None:
            return
        self._broadcast(self.lobby.lobby_state(), reliable=True, now_ms=int(now_ms))

    def _trace_metrics(self, *, now_ms: int) -> None:
        if (int(now_ms) - int(self._metrics_last_log_ms)) < 1000:
            return
        self._metrics_last_log_ms = int(now_ms)

        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = ftol_ms_i32(float(delay_ticks) * 1000.0 / float(tick_rate))

        waiting_for = int(self.lockstep.waiting_for_inputs()) if self.lockstep is not None else 0
        stall_ms = 0
        if self.lockstep is not None and waiting_for > 0:
            stall_ms = max(0, int(now_ms) - int(self.lockstep.last_progress_ms))

        capture_tick = int(self.capture_tick)
        emit_tick = int(self.lockstep.next_emit_tick) if self.lockstep is not None else 0
        ready_frames = len(self.ready_ticks)
        buffered_ticks = int(self.lockstep.buffered_tick_count) if self.lockstep is not None else 0
        target_lead_ticks = int(capture_tick) + int(delay_ticks) - int(emit_tick)

        rtts = [int(peer.link.rtt_last_ms) for peer in self.peers.values() if peer.link.rtt_last_ms > 0]
        rtt_min = min(rtts) if rtts else 0
        rtt_max = max(rtts) if rtts else 0
        pending_max = max((int(peer.link.pending_count) for peer in self.peers.values()), default=0)
        resends_total = sum(int(peer.link.resend_count) for peer in self.peers.values())
        resends_delta = max(0, int(resends_total) - int(self._metrics_last_resends_total))
        self._metrics_last_resends_total = int(resends_total)

        lan_debug_log(
            "net_metrics",
            role="host",
            delay_ticks=int(delay_ticks),
            delay_ms=int(delay_ms),
            capture_tick=int(capture_tick),
            emit_tick=int(emit_tick),
            lead_ticks=int(capture_tick) - int(emit_tick),
            target_lead_ticks=int(target_lead_ticks),
            ready_frames=int(ready_frames),
            buffered_ticks=int(buffered_ticks),
            waiting_for=int(waiting_for),
            stall_ms=int(stall_ms),
            rtt_min_ms=int(rtt_min),
            rtt_max_ms=int(rtt_max),
            pending_max=int(pending_max),
            resends_s=int(resends_delta),
            input_latency_ms=int(self.local_input_latency_ms),
            input_latency_ewma_ms=int(self.local_input_latency_ewma_ms),
        )

    def _init_lockstep(self, event: MatchStart) -> None:
        player_count = max(1, min(4, int(event.player_count)))
        self.lockstep = HostLockstepState(
            player_count=int(player_count),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.capture_tick = 0
        self.ready_ticks.clear()
        self._pending_commands.clear()

        delay = max(0, int(self.cfg.input_delay_ticks))
        neutral = list(self._neutral_input)
        for tick in range(int(delay)):
            for slot in range(int(player_count)):
                self.lockstep.submit_input_sample(
                    slot_index=int(slot),
                    tick_index=int(tick),
                    packed_input=list(neutral),
                )


@dataclass(slots=True)
class JoinLockstepRuntime:
    """Join-side LAN lobby handshake and lockstep driver."""

    cfg: JoinLockstepRuntimeConfig
    build_id: str = field(default_factory=current_build_id)
    transport: UdpTransport = field(init=False)
    started: bool = False
    error: str = ""

    lobby: ClientLobby | None = None
    link: ReliableLink | None = None
    host_addr: PeerAddr | None = None
    last_hello_ms: int = 0
    last_seen_ms: int = 0
    lockstep: ClientLockstepState | None = None
    pause_state: PauseState | None = None
    seen_tick_frame: bool = False

    _metrics_last_log_ms: int = 0
    _metrics_last_resends_total: int = 0
    _input_queued_at_ms: dict[int, int] = field(default_factory=dict)
    local_input_latency_ms: int = 0
    local_input_latency_ewma_ms: float = 0.0

    desync_count: int = 0
    last_desync_tick: int = -1
    last_desync_kind: str = ""
    last_desync_expected: str = ""
    last_desync_actual: str = ""

    _log_forward_queue: deque[str] = field(default_factory=deque)
    _log_forward_last_flush_ms: int = 0
    _log_forward_dropped: int = 0
    _log_forward_enabled: bool = False
    _neutral_input: PackedPlayerInput = field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0, 0])
    _last_send_ms: int = 0
    last_client_send_ms: int = 0

    def __post_init__(self) -> None:
        self.transport = UdpTransport(bind_host=str(self.cfg.bind_host), bind_port=0)

    def open(self) -> None:
        if self.lobby is not None:
            return
        self.transport.open()
        self.started = False
        self.error = ""
        self._last_send_ms = 0
        self.last_client_send_ms = 0
        self._metrics_last_log_ms = 0
        self._metrics_last_resends_total = 0
        self._input_queued_at_ms.clear()
        self.local_input_latency_ms = 0
        self.local_input_latency_ewma_ms = 0.0
        _reset_desync_counters(self)
        self._log_forward_queue.clear()
        self._log_forward_last_flush_ms = 0
        self._log_forward_dropped = 0
        self.seen_tick_frame = False
        lan_debug_log(
            "net_open",
            role="join",
            bind_host=str(self.cfg.bind_host),
            bind_port=int(self.transport.bound_port),
            build_id=str(self.build_id),
            mode_id=int(self.cfg.mode_id),
            player_count=int(self.cfg.player_count),
            tick_rate=int(self.cfg.tick_rate),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )

        host_ip_raw = str(self.cfg.host_ip).strip()
        host_ip = host_ip_raw
        if host_ip_raw:
            try:
                host_ip = socket.gethostbyname(host_ip_raw)
            except OSError as exc:
                lan_debug_log("net_resolve_host_error", role="join", host=str(host_ip_raw), error=str(exc))
        self.host_addr = (str(host_ip), int(self.cfg.port))
        lan_debug_log(
            "net_resolve_host",
            role="join",
            host=str(host_ip_raw),
            resolved=str(host_ip),
            port=int(self.cfg.port),
        )
        self.link = ReliableLink()
        set_lan_debug_forwarder(self._forward_log_line)
        self._log_forward_enabled = True
        settings = session_settings_for_lockstep(
            mode_id=self.cfg.mode_id,
            player_count=int(self.cfg.player_count),
            quest_level=self.cfg.quest_level,
            preserve_bugs=bool(self.cfg.preserve_bugs),
            tick_rate=int(self.cfg.tick_rate),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        hello = hello_from_session_settings(
            settings,
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(self.build_id),
            host=False,
        )
        self.lobby = ClientLobby(build_id=str(self.build_id), hello=hello)
        self.last_hello_ms = 0
        self.last_seen_ms = _now_ms()

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.lobby = None
            self.link = None
            self.host_addr = None
            self.last_hello_ms = 0
            self.last_seen_ms = 0
            self.lockstep = None
            self.pause_state = None
            self.seen_tick_frame = False
            self._last_send_ms = 0
            self.last_client_send_ms = 0
            self._metrics_last_log_ms = 0
            self._metrics_last_resends_total = 0
            self._input_queued_at_ms.clear()
            self.local_input_latency_ms = 0
            self.local_input_latency_ewma_ms = 0.0
            _reset_desync_counters(self)
            self._log_forward_queue.clear()
            self._log_forward_last_flush_ms = 0
            self._log_forward_dropped = 0
            if self._log_forward_enabled:
                set_lan_debug_forwarder(None)
            self._log_forward_enabled = False
            self.started = False
            self.error = ""
            lan_debug_log("net_close", role="join")

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    @property
    def local_slot_index(self) -> int:
        if self.lobby is None:
            return -1
        return int(self.lobby.slot_index)

    def debug_overlay_lines(self) -> list[str]:
        lines: list[str] = []
        now_ms = _now_ms()
        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = ftol_ms_i32(float(delay_ticks) * 1000.0 / float(tick_rate))

        if self.error:
            lines.append(f"net: error={self.error}")
        if int(self.desync_count) > 0:
            exp = str(self.last_desync_expected or "")[:8]
            act = str(self.last_desync_actual or "")[:8]
            lines.append(
                "desyncs: "
                f"{int(self.desync_count)} "
                f"last={str(self.last_desync_kind or '?')}@{int(self.last_desync_tick)} "
                f"{exp}!={act}",
            )

        host_label = f"{self.host_addr[0]}:{self.host_addr[1]}" if self.host_addr is not None else "?:?"
        joined = bool(self.lobby.joined) if self.lobby is not None else False
        started = bool(self.lobby.started) if self.lobby is not None else False
        slot = int(self.lobby.slot_index) if self.lobby is not None else -1

        consume_tick = 0
        buffered_frames = 0
        stall_ms = 0
        paused = 0
        if self.lockstep is not None:
            consume_tick = int(self.lockstep.next_consume_tick)
            buffered_frames = int(self.lockstep.buffered_frame_count)
            paused = int(self.lockstep.paused)
            if int(self.lockstep.buffered_frame_count) <= 0:
                stall_ms = max(0, int(now_ms) - int(self.lockstep.last_progress_ms))

        rtt_last = int(self.link.rtt_last_ms) if self.link is not None else 0
        rtt_ewma = int(self.link.rtt_ewma_ms) if self.link is not None else 0
        pending = int(self.link.pending_count) if self.link is not None else 0

        lines.append(
            "net(join): "
            f"host={host_label} "
            f"slot={int(slot)} "
            f"joined={int(joined)} "
            f"started={int(started)} "
            f"consume={int(consume_tick)} "
            f"buf={int(buffered_frames)} "
            f"stall={int(stall_ms)}ms "
            f"pause={int(paused)}",
        )
        lines.append(
            "link(join): "
            f"delay={delay_ticks}t({delay_ms}ms) "
            f"rtt={int(rtt_last)}/{int(rtt_ewma)}ms "
            f"pending={int(pending)}",
        )
        if self.pause_state is not None and bool(self.pause_state.paused):
            lines.append(f"pause: {str(self.pause_state.reason or '')}")
        return lines

    def lobby_state(self) -> LobbyState | None:
        if self.lobby is None:
            return None
        return self.lobby.lobby_state_latest

    def match_start(self) -> MatchStart | None:
        if self.lobby is None:
            return None
        return self.lobby.match_start

    def note_desync(self, *, kind: str, tick_index: int, expected: str, actual: str) -> None:
        _note_desync(role="join", runtime=self, kind=kind, tick_index=tick_index, expected=expected, actual=actual)

    def host_remote_inputs_ready(self) -> bool:
        return True

    def queue_local_input(self, packed_input: PackedPlayerInput, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        if self.lockstep is None:
            return
        batch = self.lockstep.queue_local_input(list(packed_input))
        used_capture_tick = int(self.lockstep.capture_tick) - 1
        target_tick = int(used_capture_tick) + int(self.lockstep.input_delay_ticks)
        self._input_queued_at_ms[int(target_tick)] = int(now_ms)
        self._send(batch, reliable=False, now_ms=int(now_ms))

    def pop_tick_frame(self) -> TickFrame | None:
        if self.lockstep is None:
            return None
        return self.lockstep.pop_canonical_frame()

    def submit_local_command(self, command: GameCommand) -> None:
        _ = command

    def broadcast_tick_frame(self, frame: TickFrame, *, now_ms: int | None = None) -> None:
        _ = frame, now_ms

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        self._update(now_ms=int(now_ms))
        self._trace_metrics(now_ms=int(now_ms))

    def _set_error(self, reason: str) -> None:
        if self.error:
            return
        self.error = str(reason)
        if self._log_forward_enabled:
            set_lan_debug_forwarder(None)
        self._log_forward_enabled = False
        self._log_forward_queue.clear()

    def _forward_log_line(self, line: str) -> None:
        if not bool(self._log_forward_enabled):
            return
        if len(self._log_forward_queue) >= int(CLIENT_LOG_FORWARD_MAX_QUEUE_LINES):
            self._log_forward_queue.popleft()
            self._log_forward_dropped = int(self._log_forward_dropped) + 1
        self._log_forward_queue.append(str(line))

    def _flush_forwarded_logs(self, *, now_ms: int) -> None:
        if not bool(self._log_forward_enabled):
            return
        if (int(now_ms) - int(self._log_forward_last_flush_ms)) < int(CLIENT_LOG_FORWARD_FLUSH_MS):
            return
        if (not self._log_forward_queue) and int(self._log_forward_dropped) <= 0:
            return
        if self.lobby is None:
            return
        welcome = self.lobby.welcome
        if welcome is None or not bool(welcome.accepted):
            return
        slot_index = int(welcome.slot_index)
        if int(slot_index) <= 0:
            return

        lines: list[str] = []
        chars = 0
        dropped = int(self._log_forward_dropped)
        if dropped > 0:
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
            drop_line = f"{timestamp} event=log_forward_drop dropped={int(dropped)}\n"
            lines.append(drop_line)
            chars += len(drop_line)
            self._log_forward_dropped = 0

        while self._log_forward_queue and len(lines) < int(CLIENT_LOG_FORWARD_MAX_LINES_PER_BATCH):
            next_line = str(self._log_forward_queue[0])
            if lines and (int(chars) + len(next_line)) > int(CLIENT_LOG_FORWARD_MAX_CHARS_PER_BATCH):
                break
            if (not lines) and len(next_line) > int(CLIENT_LOG_FORWARD_MAX_CHARS_PER_BATCH):
                lines.append(str(self._log_forward_queue.popleft()))
                break
            lines.append(str(self._log_forward_queue.popleft()))
            chars += len(lines[-1])

        if not lines:
            return

        self._log_forward_last_flush_ms = int(now_ms)
        try:
            self._send(DebugLogBatch(slot_index=int(slot_index), lines=lines), reliable=False, now_ms=int(now_ms))
        except OSError:
            return

    def _update(self, *, now_ms: int) -> None:
        if self.lobby is None or self.link is None or self.host_addr is None:
            return
        if self.error:
            return

        if (
            self.lobby.welcome is None
            and int(self.link.pending_count) <= 0
            and (int(now_ms) - int(self.last_hello_ms)) >= 200
        ):
            self.last_hello_ms = int(now_ms)
            self._send(self.lobby.hello, reliable=True, now_ms=int(now_ms))

        for addr, packet in self.transport.recv_packets(max_packets=int(MAX_RECV_PACKETS_PER_UPDATE)):
            if addr != self.host_addr:
                continue
            self.last_seen_ms = int(now_ms)
            messages, dup = self.link.ingest_packet(packet, now_ms=int(now_ms))
            if dup:
                lan_debug_log("net_recv_dup", role="join", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_message(message, now_ms=int(now_ms))
                if self.error:
                    return

        timeout_ms = int(LINK_TIMEOUT_MS)
        if bool(self.started) and (not bool(self.seen_tick_frame)):
            timeout_ms = int(LOADING_LINK_TIMEOUT_MS)
        if (
            bool(self.started)
            and self.pause_state is not None
            and bool(self.pause_state.paused)
            and str(self.pause_state.reason or "") == "waiting_input"
        ):
            timeout_ms = max(int(timeout_ms), int(PAUSED_LINK_TIMEOUT_MS))
        if (int(now_ms) - int(self.last_seen_ms)) >= int(timeout_ms):
            if not self.error:
                self._set_error("timeout")
                lan_debug_log(
                    "net_timeout",
                    role="join",
                    addr=f"{self.host_addr[0]}:{self.host_addr[1]}",
                    timeout_ms=int(timeout_ms),
                    started=bool(self.started),
                    seen_tick_frame=bool(self.seen_tick_frame),
                )
            return

        self._flush_forwarded_logs(now_ms=int(now_ms))

        for resend in self.link.poll_resends(now_ms=int(now_ms)):
            try:
                self.transport.send_packet(self.host_addr, resend)
            except OSError:
                continue
            self._last_send_ms = int(now_ms)

        if bool(self.started):
            last_send = int(self._last_send_ms)
            if last_send <= 0:
                self._last_send_ms = int(now_ms)
            elif (int(now_ms) - int(last_send)) >= int(KEEPALIVE_INTERVAL_MS):
                tick_index = int(self.lockstep.next_consume_tick) if self.lockstep is not None else 0
                self._send(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

        self._send_idle_heartbeat(now_ms=int(now_ms))

    def _handle_message(self, message: NetMessage, *, now_ms: int) -> None:
        if self.lobby is None:
            return
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, Welcome):
            lan_debug_log(
                "net_recv",
                role="join",
                kind="welcome",
                accepted=bool(message.accepted),
                reason=str(message.reason or ""),
                slot_index=int(message.slot_index),
                session_id=str(message.session_id),
                protocol_version=int(message.protocol_version),
                build_id=str(message.build_id or ""),
                mode_id=int(message.mode_id),
                player_count=int(message.player_count),
                tick_rate=int(message.tick_rate),
                input_delay_ticks=int(message.input_delay_ticks),
                quest_level=str(message.quest_level or ""),
                preserve_bugs=bool(message.preserve_bugs),
                started=bool(message.started),
            )
            self.lobby.ingest_welcome(message)
            if not bool(message.accepted):
                self._set_error(str(message.reason or "rejected"))
                return
            welcome_settings = session_settings_from_welcome(message)
            hello = self.lobby.hello
            if hello is not None:
                hello_settings = session_settings_from_hello(hello)
                if hello_settings != welcome_settings:
                    lan_debug_log(
                        "net_welcome_override",
                        role="join",
                        hello_mode_id=int(hello_settings.mode_id),
                        welcome_mode_id=int(welcome_settings.mode_id),
                        hello_player_count=int(hello_settings.player_count),
                        welcome_player_count=int(welcome_settings.player_count),
                        hello_tick_rate=int(hello_settings.tick_rate),
                        welcome_tick_rate=int(welcome_settings.tick_rate),
                        hello_input_delay_ticks=int(hello_settings.input_delay_ticks),
                        welcome_input_delay_ticks=int(welcome_settings.input_delay_ticks),
                        hello_quest_level=str(hello_settings.quest_level or ""),
                        welcome_quest_level=str(welcome_settings.quest_level or ""),
                        hello_preserve_bugs=bool(hello_settings.preserve_bugs),
                        welcome_preserve_bugs=bool(welcome_settings.preserve_bugs),
                    )

            self.cfg.mode_id = welcome_settings.mode_id
            self.cfg.player_count = int(welcome_settings.player_count)
            self.cfg.tick_rate = int(welcome_settings.tick_rate)
            self.cfg.input_delay_ticks = int(welcome_settings.input_delay_ticks)
            self.cfg.quest_level = welcome_settings.quest_level
            self.cfg.preserve_bugs = bool(welcome_settings.preserve_bugs)
            self._send(Ready(slot_index=int(message.slot_index), ready=True), reliable=True, now_ms=int(now_ms))
            return
        if isinstance(message, LobbyState):
            connected = sum(1 for slot in message.slots if bool(slot.connected))
            lan_debug_log(
                "net_recv",
                role="join",
                kind="lobby_state",
                session_id=str(message.session_id),
                player_count=int(message.player_count),
                connected=int(connected),
                all_ready=bool(message.all_ready),
                started=bool(message.started),
            )
            self.lobby.ingest_lobby_state(message)
            return
        if isinstance(message, MatchStart):
            status_snapshot = message.status_snapshot
            status_unlock = int(status_snapshot.quest_unlock_index) if status_snapshot is not None else 0
            status_unlock_full = int(status_snapshot.quest_unlock_index_full) if status_snapshot is not None else 0
            lan_debug_log(
                "net_recv",
                role="join",
                kind="match_start",
                session_id=str(message.session_id),
                mode_id=int(message.mode_id),
                player_count=int(message.player_count),
                seed=int(message.seed),
                start_tick=int(message.start_tick),
                quest_level=str(message.quest_level or ""),
                preserve_bugs=bool(message.preserve_bugs),
                status_quest_unlock_index=int(status_unlock),
                status_quest_unlock_index_full=int(status_unlock_full),
            )
            welcome = self.lobby.welcome
            if welcome is not None and str(welcome.session_id or ""):
                if str(message.session_id or "") != str(welcome.session_id or ""):
                    self._set_error("session_id_mismatch")
                    lan_debug_log(
                        "net_sanity_mismatch",
                        role="join",
                        kind="match_start",
                        expected_session_id=str(welcome.session_id or ""),
                        actual_session_id=str(message.session_id or ""),
                    )
                    return

            expected_settings = session_settings_for_lockstep(
                mode_id=self.cfg.mode_id,
                player_count=int(self.cfg.player_count),
                quest_level=self.cfg.quest_level,
                preserve_bugs=bool(self.cfg.preserve_bugs),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
            )
            match_settings = session_settings_from_match_start(
                message,
                tick_rate=int(expected_settings.tick_rate),
                input_delay_ticks=int(expected_settings.input_delay_ticks),
            )
            if match_settings != expected_settings:
                self._set_error("match_start_mismatch")
                lan_debug_log(
                    "net_sanity_mismatch",
                    role="join",
                    kind="match_start",
                    expected_mode_id=int(expected_settings.mode_id),
                    actual_mode_id=int(match_settings.mode_id),
                    expected_player_count=int(expected_settings.player_count),
                    actual_player_count=int(match_settings.player_count),
                    expected_quest_level=str(expected_settings.quest_level or ""),
                    actual_quest_level=str(match_settings.quest_level or ""),
                    expected_preserve_bugs=bool(expected_settings.preserve_bugs),
                    actual_preserve_bugs=bool(match_settings.preserve_bugs),
                )
                return

            if status_snapshot is None:
                self._set_error("match_start_missing_status_snapshot")
                lan_debug_log("net_sanity_error", role="join", kind="match_start", reason=str(self.error))
                return

            self.lobby.ingest_match_start(message)
            self.started = True
            self._init_lockstep()
            return
        if isinstance(message, TickFrame):
            self.seen_tick_frame = True
            if self.lockstep is None:
                return
            tick = int(message.tick_index)
            if int(tick) < 0:
                lan_debug_log("net_sanity_error", role="join", kind="tick_frame", reason="negative_tick", tick_index=int(tick))
                return
            inputs_len = len(message.frame_inputs)
            if int(inputs_len) != int(self.cfg.player_count):
                lan_debug_log(
                    "net_sanity_error",
                    role="join",
                    kind="tick_frame",
                    reason="frame_inputs_len",
                    tick_index=int(tick),
                    inputs_len=int(inputs_len),
                    expected_len=int(self.cfg.player_count),
                )
            if int(tick) < 5 or (int(tick) % 60) == 0:
                lan_debug_log("net_recv", role="join", kind="tick_frame", tick_index=int(tick), command_count=len(message.commands))
            self.lockstep.ingest_tick_frame(message, now_ms=int(now_ms))
            queued_at = self._input_queued_at_ms.pop(int(tick), None)
            if queued_at is not None:
                latency_ms = max(0, int(now_ms) - int(queued_at))
                self.local_input_latency_ms = int(latency_ms)
                if self.local_input_latency_ewma_ms <= 0.0:
                    self.local_input_latency_ewma_ms = float(latency_ms)
                else:
                    self.local_input_latency_ewma_ms = float(
                        self.local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1,
                    )
            return
        if isinstance(message, PauseState):
            lan_debug_log(
                "net_recv",
                role="join",
                kind="pause_state",
                paused=bool(message.paused),
                reason=str(message.reason or ""),
            )
            self.pause_state = message
            return
        if isinstance(message, Disconnect):
            lan_debug_log("net_recv", role="join", kind="disconnect", reason=str(message.reason or ""))
            self._set_error(str(message.reason or "disconnect"))
            return
        lan_debug_log("net_recv", role="join", kind=type(message).__name__)

    def _send(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        if self.link is None or self.host_addr is None:
            return
        packet = self.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(self.host_addr, packet)
        except OSError:
            return
        self._last_send_ms = int(now_ms)
        self.last_client_send_ms = int(now_ms)
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, DebugLogBatch):
            return
        if isinstance(message, InputBatch):
            max_tick = -1
            min_tick = 2**31 - 1
            for sample in message.samples:
                tick = int(sample.tick_index)
                max_tick = max(int(max_tick), int(tick))
                min_tick = min(int(min_tick), int(tick))
            if max_tick >= 0 and (int(max_tick) < 5 or (int(max_tick) % 60) == 0):
                lan_debug_log(
                    "net_send",
                    role="join",
                    kind="input_batch",
                    reliable=bool(reliable),
                    slot_index=int(message.slot_index),
                    sample_count=len(message.samples),
                    tick_min=int(min_tick) if min_tick != 2**31 - 1 else 0,
                    tick_max=int(max_tick),
                )
            return
        lan_debug_log("net_send", role="join", kind=type(message).__name__, reliable=bool(reliable))

    def _send_idle_heartbeat(self, *, now_ms: int) -> None:
        if not bool(self.started):
            return
        if self.pause_state is None or (not bool(self.pause_state.paused)) or str(self.pause_state.reason or "") != "waiting_input":
            return
        if (int(now_ms) - int(self.last_client_send_ms)) < int(IDLE_HEARTBEAT_MS):
            return
        if self.lobby is None or self.link is None:
            return
        if int(self.link.pending_count) > 0:
            return
        self._send(InputBatch(slot_index=int(self.lobby.slot_index), samples=[]), reliable=False, now_ms=int(now_ms))

    def _trace_metrics(self, *, now_ms: int) -> None:
        if (int(now_ms) - int(self._metrics_last_log_ms)) < 1000:
            return
        self._metrics_last_log_ms = int(now_ms)

        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = ftol_ms_i32(float(delay_ticks) * 1000.0 / float(tick_rate))

        pending = int(self.link.pending_count) if self.link is not None else 0
        resends_total = int(self.link.resend_count) if self.link is not None else 0
        resends_delta = max(0, int(resends_total) - int(self._metrics_last_resends_total))
        self._metrics_last_resends_total = int(resends_total)

        stall_ms = 0
        if self.lockstep is not None and int(self.lockstep.buffered_frame_count) <= 0:
            stall_ms = max(0, int(now_ms) - int(self.lockstep.last_progress_ms))

        capture_tick = int(self.lockstep.capture_tick) if self.lockstep is not None else 0
        consume_tick = int(self.lockstep.next_consume_tick) if self.lockstep is not None else 0
        buffered_frames = int(self.lockstep.buffered_frame_count) if self.lockstep is not None else 0
        lan_debug_log(
            "net_metrics",
            role="join",
            delay_ticks=int(delay_ticks),
            delay_ms=int(delay_ms),
            stall_ms=int(stall_ms),
            capture_tick=int(capture_tick),
            consume_tick=int(consume_tick),
            lead_ticks=int(capture_tick) - int(consume_tick),
            buffered_frames=int(buffered_frames),
            rtt_ms=int(self.link.rtt_last_ms) if self.link is not None else 0,
            rtt_ewma_ms=int(self.link.rtt_ewma_ms) if self.link is not None else 0,
            pending=int(pending),
            resends_s=int(resends_delta),
            input_latency_ms=int(self.local_input_latency_ms),
            input_latency_ewma_ms=int(self.local_input_latency_ewma_ms),
        )

    def _init_lockstep(self) -> None:
        self.lockstep = ClientLockstepState(
            local_slot_index=int(self.local_slot_index),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.pause_state = None
        self.seen_tick_frame = False


LockstepRuntime: TypeAlias = HostLockstepRuntime | JoinLockstepRuntime


__all__ = [
    "HostLockstepRuntime",
    "HostLockstepRuntimeConfig",
    "JoinLockstepRuntime",
    "JoinLockstepRuntimeConfig",
    "LockstepRuntime",
    "LockstepRuntimeConfig",
]
