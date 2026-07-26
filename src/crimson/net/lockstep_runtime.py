from __future__ import annotations

import datetime as dt
import socket
import time
from collections import deque
from pathlib import Path
from typing import Literal, cast

import msgspec

from ..game_modes import GameMode
from ..persistence.save_status import GameStatusData
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
    sim_status: GameStatusData | None = None


class HostLockstepRuntimeConfig(_LockstepRuntimeConfigBase):
    role: Literal["host"] = "host"


class JoinLockstepRuntimeConfig(_LockstepRuntimeConfigBase):
    role: Literal["join"] = "join"


type LockstepRuntimeConfig = HostLockstepRuntimeConfig | JoinLockstepRuntimeConfig


class _HostPeerLink(msgspec.Struct):
    addr: PeerAddr
    link: ReliableLink = msgspec.field(default_factory=ReliableLink)
    last_seen_ms: int = 0


class LockstepRuntime(msgspec.Struct):
    """Drive LAN lobby handshake and keep socket state alive across views."""

    cfg: LockstepRuntimeConfig
    build_id: str = msgspec.field(default_factory=current_build_id)
    transport: UdpTransport = cast(UdpTransport, None)
    started: bool = False
    error: str = ""

    host_lobby: HostLobby | None = None
    host_peers: dict[PeerAddr, _HostPeerLink] = msgspec.field(default_factory=dict)
    host_seed: int = 0
    host_match_start: MatchStart | None = None
    host_last_broadcast_ms: int = 0
    host_lockstep: HostLockstepState | None = None
    host_capture_tick: int = 0
    host_ready_ticks: deque[HostReadyTick] = msgspec.field(default_factory=deque)
    _pending_host_commands: list[GameCommand] = msgspec.field(default_factory=list)
    _host_seen_input_slots: set[int] = msgspec.field(default_factory=set)

    client_lobby: ClientLobby | None = None
    client_link: ReliableLink | None = None
    client_host_addr: PeerAddr | None = None
    client_last_hello_ms: int = 0
    client_last_seen_ms: int = 0
    _client_last_send_ms: int = 0
    client_lockstep: ClientLockstepState | None = None
    client_pause_state: PauseState | None = None
    _client_seen_tick_frame: bool = False
    _last_send_ms: int = 0

    # Instrumentation (debug overlay + lan debug logs).
    _metrics_last_log_ms: int = 0
    _metrics_last_resends_total: int = 0

    _host_input_queued_at_ms: dict[int, int] = msgspec.field(default_factory=dict)
    _host_local_input_latency_ms: int = 0
    _host_local_input_latency_ewma_ms: float = 0.0

    _client_input_queued_at_ms: dict[int, int] = msgspec.field(default_factory=dict)
    _client_local_input_latency_ms: int = 0
    _client_local_input_latency_ewma_ms: float = 0.0

    desync_count: int = 0
    last_desync_tick: int = -1
    last_desync_kind: str = ""
    last_desync_expected: str = ""
    last_desync_actual: str = ""


    _client_log_forward_queue: deque[str] = msgspec.field(default_factory=deque)
    _client_log_forward_last_flush_ms: int = 0
    _client_log_forward_dropped: int = 0
    _client_log_forward_enabled: bool = False

    _host_remote_log_paths: dict[int, Path] = msgspec.field(default_factory=dict)

    _neutral_input: PackedPlayerInput = msgspec.field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0, 0],)

    def __post_init__(self) -> None:
        bind_port = int(self.cfg.port) if str(self.cfg.role) == "host" else 0
        self.transport = UdpTransport(bind_host=str(self.cfg.bind_host), bind_port=int(bind_port))

    def open(self) -> None:
        if self.host_lobby is not None or self.client_lobby is not None:
            return
        self.transport.open()
        self._last_send_ms = 0
        self._metrics_last_log_ms = 0
        self._metrics_last_resends_total = 0
        self._host_input_queued_at_ms.clear()
        self._host_local_input_latency_ms = 0
        self._host_local_input_latency_ewma_ms = 0.0
        self._client_input_queued_at_ms.clear()
        self._client_local_input_latency_ms = 0
        self._client_local_input_latency_ewma_ms = 0.0
        self._host_seen_input_slots.clear()
        self.desync_count = 0
        self.last_desync_tick = -1
        self.last_desync_kind = ""
        self.last_desync_expected = ""
        self.last_desync_actual = ""

        self._client_log_forward_queue.clear()
        self._client_log_forward_last_flush_ms = 0
        self._client_log_forward_dropped = 0
        self._client_log_forward_enabled = False
        self._host_remote_log_paths.clear()
        self._client_seen_tick_frame = False
        lan_debug_log(
            "net_open",
            role=str(self.cfg.role),
            bind_host=str(self.cfg.bind_host),
            bind_port=int(self.transport.bound_port),
            build_id=str(self.build_id),
            mode_id=int(self.cfg.mode_id),
            player_count=int(self.cfg.player_count),
            tick_rate=int(self.cfg.tick_rate),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        if str(self.cfg.role) == "host":
            self.host_lobby = HostLobby(
                mode_id=self.cfg.mode_id,
                player_count=int(self.cfg.player_count),
                build_id=str(self.build_id),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
                quest_level=self.cfg.quest_level,
                preserve_bugs=bool(self.cfg.preserve_bugs),
            )
            self.host_last_broadcast_ms = _now_ms()
        else:
            host_ip_raw = str(self.cfg.host_ip).strip()
            host_ip = host_ip_raw
            if host_ip_raw:
                try:
                    host_ip = socket.gethostbyname(host_ip_raw)
                except OSError as exc:
                    lan_debug_log("net_resolve_host_error", role="join", host=str(host_ip_raw), error=str(exc))
            self.client_host_addr = (str(host_ip), int(self.cfg.port))
            lan_debug_log(
                "net_resolve_host",
                role="join",
                host=str(host_ip_raw),
                resolved=str(host_ip),
                port=int(self.cfg.port),
            )
            self.client_link = ReliableLink()
            set_lan_debug_forwarder(self._client_forward_log_line)
            self._client_log_forward_enabled = True
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
            self.client_lobby = ClientLobby(build_id=str(self.build_id), hello=hello)
            self.client_last_hello_ms = 0
            self.client_last_seen_ms = _now_ms()
            self._client_last_send_ms = 0

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.host_lobby = None
            self.host_peers.clear()
            self.host_seed = 0
            self.host_match_start = None
            self.host_last_broadcast_ms = 0
            self.client_lobby = None
            self.client_link = None
            self.client_host_addr = None
            self.client_last_hello_ms = 0
            self.client_last_seen_ms = 0
            self._client_last_send_ms = 0
            self.host_lockstep = None
            self.host_capture_tick = 0
            self.host_ready_ticks.clear()
            self._pending_host_commands.clear()
            self.client_lockstep = None
            self.client_pause_state = None
            self._last_send_ms = 0
            self._metrics_last_log_ms = 0
            self._metrics_last_resends_total = 0
            self._host_input_queued_at_ms.clear()
            self._host_local_input_latency_ms = 0
            self._host_local_input_latency_ewma_ms = 0.0
            self._client_input_queued_at_ms.clear()
            self._client_local_input_latency_ms = 0
            self._client_local_input_latency_ewma_ms = 0.0
            self._host_seen_input_slots.clear()
            self.desync_count = 0
            self.last_desync_tick = -1
            self.last_desync_kind = ""
            self.last_desync_expected = ""
            self.last_desync_actual = ""
    
            self._client_log_forward_queue.clear()
            self._client_log_forward_last_flush_ms = 0
            self._client_log_forward_dropped = 0
            if self._client_log_forward_enabled:
                set_lan_debug_forwarder(None)
            self._client_log_forward_enabled = False
            self._host_remote_log_paths.clear()
            self._client_seen_tick_frame = False
            self.started = False
            self.error = ""
            lan_debug_log("net_close", role=str(self.cfg.role))

    def host_remote_inputs_ready(self) -> bool:
        """True once each remote slot has sent at least one InputBatch.

        This is used to gate the host's first simulation steps so the host doesn't
        start capturing inputs before joiners have entered gameplay, which can
        create persistent host-side input latency.
        """
        if str(self.cfg.role) != "host":
            return True
        lockstep = self.host_lockstep
        if lockstep is None:
            return False
        player_count = max(1, int(lockstep.player_count))
        for slot in range(1, int(player_count)):
            if int(slot) not in self._host_seen_input_slots:
                return False
        return True

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    def debug_overlay_lines(self) -> list[str]:
        """Return compact LAN debug HUD lines for in-game overlays."""
        lines: list[str] = []
        role = str(self.cfg.role)
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
                f"last={self.last_desync_kind or '?'!s}@{int(self.last_desync_tick)} "
                f"{exp}!={act}",
            )

        if role == "host":
            peer_total = max(0, int(self.cfg.player_count) - 1)
            lockstep = self.host_lockstep
            emit_tick = 0
            lead_ticks = 0
            waiting_for = 0
            stall_ms = 0
            if lockstep is not None:
                emit_tick = int(lockstep.next_emit_tick)
                lead_ticks = int(self.host_capture_tick) - int(emit_tick)
                waiting_for = int(lockstep.waiting_for_inputs())
                if waiting_for > 0:
                    stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))
            rtts = [int(peer.link.rtt_last_ms) for peer in self.host_peers.values() if peer.link.rtt_last_ms > 0]
            rtt_label = "?"
            if rtts:
                rtt_label = f"{min(rtts)}..{max(rtts)}"
            pending_max = max((int(peer.link.pending_count) for peer in self.host_peers.values()), default=0)
            lines.append(
                "net(host): "
                f"peers={len(self.host_peers)}/{int(peer_total)} "
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

        lobby = self.client_lobby
        host = self.client_host_addr
        host_label = f"{host[0]}:{host[1]}" if host is not None else "?:?"
        joined = bool(lobby.joined) if lobby is not None else False
        started = bool(lobby.started) if lobby is not None else False
        slot = int(lobby.slot_index) if lobby is not None else -1

        lockstep = self.client_lockstep
        consume_tick = 0
        buffered_frames = 0
        stall_ms = 0
        paused = 0
        if lockstep is not None:
            consume_tick = int(lockstep.next_consume_tick)
            buffered_frames = int(lockstep.buffered_frame_count)
            paused = int(lockstep.paused)
            if int(lockstep.buffered_frame_count) <= 0:
                stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))

        link = self.client_link
        rtt_last = 0
        rtt_ewma = 0
        pending = 0
        if link is not None:
            rtt_last = int(link.rtt_last_ms)
            rtt_ewma = int(link.rtt_ewma_ms)
            pending = int(link.pending_count)

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
        pause = self.client_pause_state
        if pause is not None and bool(pause.paused):
            lines.append(f"pause: {pause.reason or ''!s}")

        return lines

    def lobby_state(self) -> LobbyState | None:
        if str(self.cfg.role) == "host":
            lobby = self.host_lobby
            if lobby is None:
                return None
            return lobby.lobby_state()
        lobby = self.client_lobby
        if lobby is None:
            return None
        return lobby.lobby_state_latest

    def match_start(self) -> MatchStart | None:
        if str(self.cfg.role) == "host":
            return self.host_match_start
        lobby = self.client_lobby
        if lobby is None:
            return None
        return lobby.match_start

    @property
    def local_slot_index(self) -> int:
        if str(self.cfg.role) == "host":
            return 0
        lobby = self.client_lobby
        if lobby is None:
            return -1
        return int(lobby.slot_index)

    def note_desync(self, *, kind: str, tick_index: int, expected: str, actual: str) -> None:
        """Record a desync event and (optionally) notify the host.

        For now, desync detection is driven by gameplay modes comparing local
        hashes with those embedded in host tick frames.
        """
        self.desync_count = int(self.desync_count) + 1
        self.last_desync_tick = int(tick_index)
        self.last_desync_kind = str(kind)
        self.last_desync_expected = str(expected)
        self.last_desync_actual = str(actual)
        lan_debug_log(
            "lan_desync",
            role=str(self.cfg.role),
            kind=str(kind),
            tick_index=int(tick_index),
            expected=str(expected),
            actual=str(actual),
        )


    def _set_client_error(self, reason: str) -> None:
        if self.error:
            return
        self.error = str(reason)
        # Once client enters a terminal error state, stop forwarding local logs.
        if self._client_log_forward_enabled:
            set_lan_debug_forwarder(None)
        self._client_log_forward_enabled = False
        self._client_log_forward_queue.clear()

    def _abort_host_match(self, *, reason: str, now_ms: int, addr: PeerAddr | None = None) -> None:
        if not bool(self.started):
            return
        if self.error:
            return
        self.error = str(reason)
        details: dict[str, object] = {
            "role": "host",
            "reason": str(reason),
        }
        if addr is not None:
            details["addr"] = f"{addr[0]}:{int(addr[1])}"
        lan_debug_log("net_match_abort", **details)
        self._host_broadcast(Disconnect(reason=str(reason)), reliable=True, now_ms=int(now_ms))

    def _client_forward_log_line(self, line: str) -> None:
        # Best-effort: keep a bounded queue of recent log lines.
        if not bool(self._client_log_forward_enabled):
            return
        if str(self.cfg.role) != "join":
            return
        if len(self._client_log_forward_queue) >= int(CLIENT_LOG_FORWARD_MAX_QUEUE_LINES):
            self._client_log_forward_queue.popleft()
            self._client_log_forward_dropped = int(self._client_log_forward_dropped) + 1
        self._client_log_forward_queue.append(str(line))

    def _client_flush_forwarded_logs(self, *, now_ms: int) -> None:
        if not bool(self._client_log_forward_enabled):
            return
        if (int(now_ms) - int(self._client_log_forward_last_flush_ms)) < int(CLIENT_LOG_FORWARD_FLUSH_MS):
            return

        if (not self._client_log_forward_queue) and int(self._client_log_forward_dropped) <= 0:
            return

        lobby = self.client_lobby
        if lobby is None:
            return
        welcome = lobby.welcome
        if welcome is None or not bool(welcome.accepted):
            return
        slot_index = int(welcome.slot_index)
        if int(slot_index) <= 0:
            return

        lines: list[str] = []
        chars = 0
        dropped = int(self._client_log_forward_dropped)
        if dropped > 0:
            timestamp = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
            drop_line = f"{timestamp} event=log_forward_drop dropped={int(dropped)}\n"
            lines.append(drop_line)
            chars += len(drop_line)
            self._client_log_forward_dropped = 0

        while self._client_log_forward_queue and len(lines) < int(CLIENT_LOG_FORWARD_MAX_LINES_PER_BATCH):
            next_line = str(self._client_log_forward_queue[0])
            if lines and (int(chars) + len(next_line)) > int(CLIENT_LOG_FORWARD_MAX_CHARS_PER_BATCH):
                break
            if (not lines) and len(next_line) > int(CLIENT_LOG_FORWARD_MAX_CHARS_PER_BATCH):
                # Oversized line: still forward it (single line batch).
                lines.append(str(self._client_log_forward_queue.popleft()))
                break
            lines.append(str(self._client_log_forward_queue.popleft()))
            chars += len(lines[-1])

        if not lines:
            return

        self._client_log_forward_last_flush_ms = int(now_ms)
        try:
            self._client_send(
                DebugLogBatch(slot_index=int(slot_index), lines=lines),
                reliable=False,
                now_ms=int(now_ms),
            )
        except OSError:
            # Don't let debug log forwarding affect gameplay.
            return

    def _host_write_remote_log_batch(self, *, addr: PeerAddr, slot_index: int, lines: list[str]) -> None:
        if int(slot_index) <= 0:
            return
        if not lines:
            return

        path = self._host_remote_log_paths.get(int(slot_index))
        if path is None:
            host_path = lan_debug_log_path()
            if host_path is None:
                return
            safe_ip = str(addr[0]).replace(":", "_").replace("/", "_")
            timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
            path = host_path.parent / f"lan-client-slot{int(slot_index)}-from{safe_ip}-{int(addr[1])}-{timestamp}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            session_id = ""
            lobby = self.host_lobby
            if lobby is not None:
                session_id = str(lobby.session_id)
            init_ts = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
            init_line = (
                f"{init_ts} event=remote_log_init slot_index={int(slot_index)} "
                f"addr={addr[0]}:{int(addr[1])} session_id={session_id}\n"
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(init_line)
            self._host_remote_log_paths[int(slot_index)] = path

        with path.open("a", encoding="utf-8") as handle:
            for line in lines:
                text = str(line)
                if not text.endswith("\n"):
                    text += "\n"
                handle.write(text)

    def queue_local_input(self, packed_input: PackedPlayerInput, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        if str(self.cfg.role) == "host":
            lockstep = self.host_lockstep
            if lockstep is None:
                return
            # Keep the host capture clock close to lockstep progress. Otherwise
            # even short stalls can cause the host to queue inputs far in the
            # future, which shows up as persistent host-side input latency.
            max_capture_tick = int(lockstep.next_emit_tick) + int(HOST_MAX_CAPTURE_LEAD_TICKS)
            if int(self.host_capture_tick) > int(max_capture_tick):
                self.host_capture_tick = int(max_capture_tick)
            target_tick = int(self.host_capture_tick) + int(self.cfg.input_delay_ticks)
            self._host_input_queued_at_ms[int(target_tick)] = int(now_ms)
            lockstep.submit_input_sample(
                slot_index=0,
                tick_index=int(target_tick),
                packed_input=list(packed_input),
            )
            self.host_capture_tick += 1
            return

        lockstep = self.client_lockstep
        if lockstep is None:
            return
        batch = lockstep.queue_local_input(list(packed_input))
        # The client lockstep can clamp its internal capture tick to stay close to
        # lockstep progress, so compute the actual target tick after enqueuing.
        used_capture_tick = int(lockstep.capture_tick) - 1
        target_tick = int(used_capture_tick) + int(lockstep.input_delay_ticks)
        self._client_input_queued_at_ms[int(target_tick)] = int(now_ms)
        self._client_send(batch, reliable=False, now_ms=int(now_ms))

    def pop_tick_frame(self) -> TickFrame | None:
        if str(self.cfg.role) == "host":
            if not self.host_ready_ticks:
                return None
            ready = self.host_ready_ticks.popleft()
            commands = list(self._pending_host_commands)
            self._pending_host_commands.clear()
            return TickFrame(
                tick_index=int(ready.tick_index),
                frame_inputs=[list(packed) for packed in ready.frame_inputs],
                commands=commands,
            )
        lockstep = self.client_lockstep
        if lockstep is None:
            return None
        return lockstep.pop_canonical_frame()

    def submit_local_command(self, command: GameCommand) -> None:
        if str(self.cfg.role) != "host":
            return
        self._pending_host_commands.append(command)

    def broadcast_tick_frame(self, frame: TickFrame, *, now_ms: int | None = None) -> None:
        if str(self.cfg.role) != "host":
            return
        if now_ms is None:
            now_ms = _now_ms()
        self._host_broadcast(frame, reliable=True, now_ms=int(now_ms))

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        if str(self.cfg.role) == "host":
            self._update_host(now_ms=int(now_ms))
        else:
            self._update_client(now_ms=int(now_ms))
        self._trace_metrics(now_ms=int(now_ms))

    def _update_host(self, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return

        for addr, packet in self.transport.recv_packets(max_packets=int(MAX_RECV_PACKETS_PER_UPDATE)):
            peer_link = self.host_peers.get(addr)
            if peer_link is None:
                message = packet.message
                if isinstance(message, Hello):
                    self._handle_host_message(addr, message, now_ms=int(now_ms))
                    accepted_peer = self.host_peers.get(addr)
                    if (
                        accepted_peer is not None
                        and bool(packet.reliable)
                        and int(packet.seq) > 0
                    ):
                        accepted_peer.link.prime_recv_seq(int(packet.seq))
                continue
            peer_link.last_seen_ms = int(now_ms)
            messages, dup = peer_link.link.ingest_packet(packet, now_ms=int(now_ms))
            if dup:
                lan_debug_log("net_recv_dup", role="host", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_host_message(addr, message, now_ms=int(now_ms))

        # Drop timed-out peers.
        timeout_ms = int(LINK_TIMEOUT_MS)
        if bool(lobby.started) and (not bool(self.host_remote_inputs_ready())):
            timeout_ms = int(LOADING_LINK_TIMEOUT_MS)
        lockstep = self.host_lockstep
        if bool(lobby.started) and lockstep is not None and bool(lockstep.paused):
            timeout_ms = max(int(timeout_ms), int(PAUSED_LINK_TIMEOUT_MS))
        for addr, peer in list(self.host_peers.items()):
            if (int(now_ms) - int(peer.last_seen_ms)) < int(timeout_ms):
                continue
            slot = lobby.slot_for_addr(addr)
            self.host_peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            if slot is not None:
                self._host_seen_input_slots.discard(int(slot))
            lan_debug_log(
                "net_timeout",
                role="host",
                addr=f"{addr[0]}:{addr[1]}",
                timeout_ms=int(timeout_ms),
                started=bool(lobby.started),
            )
            if bool(lobby.started):
                self._abort_host_match(reason="peer_timeout", now_ms=int(now_ms), addr=addr)

        # Broadcast lobby state periodically.
        if (not lobby.started) and (int(now_ms) - int(self.host_last_broadcast_ms)) >= 250:
            self.host_last_broadcast_ms = int(now_ms)
            self._host_broadcast_lobby_state(now_ms=int(now_ms))

        # Start automatically once ready.
        if (not lobby.started) and lobby.all_ready():
            status = self.cfg.sim_status
            if status is None:
                self.error = "missing_sim_status"
                lan_debug_log(
                    "net_sanity_error",
                    role="host",
                    kind="match_start",
                    reason=str(self.error),
                )
                return
            self.host_seed = int((_now_ms() * 1103515245 + 12345) & 0xFFFFFFFF)
            event = lobby.start_match(
                seed=int(self.host_seed),
                status=status,
            )
            self.started = True
            self.host_match_start = event
            self._host_init_lockstep(event)
            self._host_seen_input_slots.clear()
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
                status_quest_unlock_index=int(status.quest_unlock_index),
                status_quest_unlock_index_full=int(status.quest_unlock_index_full),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
            )
            self._host_broadcast(event, reliable=True, now_ms=int(now_ms))

        if self.host_lockstep is not None:
            pause = self.host_lockstep.update_pause_state(now_ms=int(now_ms))
            if pause is not None:
                self._host_broadcast(pause, reliable=True, now_ms=int(now_ms))
            frames = self.host_lockstep.pop_ready_frames(now_ms=int(now_ms))
            for frame in frames:
                tick = int(frame.tick_index)
                queued_at = self._host_input_queued_at_ms.pop(int(tick), None)
                if queued_at is not None:
                    latency_ms = max(0, int(now_ms) - int(queued_at))
                    self._host_local_input_latency_ms = int(latency_ms)
                    if self._host_local_input_latency_ewma_ms <= 0.0:
                        self._host_local_input_latency_ewma_ms = float(latency_ms)
                    else:
                        self._host_local_input_latency_ewma_ms = float(
                            self._host_local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1,
                        )
                self.host_ready_ticks.append(frame)

        # Resend reliable packets.
        for addr, peer in self.host_peers.items():
            for resend in peer.link.poll_resends(now_ms=int(now_ms)):
                try:
                    self.transport.send_packet(addr, resend)
                except OSError:
                    continue
                self._last_send_ms = int(now_ms)

        # Prevent timeouts during stalls/pauses by sending best-effort keepalives.
        if bool(self.started) and self.host_peers:
            last_send = int(self._last_send_ms)
            if last_send <= 0:
                self._last_send_ms = int(now_ms)
            elif (int(now_ms) - int(last_send)) >= int(KEEPALIVE_INTERVAL_MS):
                tick_index = 0
                if self.host_lockstep is not None:
                    tick_index = int(self.host_lockstep.next_emit_tick)
                self._host_broadcast(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

    def _handle_host_message(self, addr: PeerAddr, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.host_lobby
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
                peer = self.host_peers.get(addr)
                if peer is None:
                    self.host_peers[addr] = _HostPeerLink(addr=addr, last_seen_ms=int(now_ms))
                else:
                    peer.last_seen_ms = int(now_ms)
            self._host_send(
                addr,
                welcome,
                reliable=True,
                now_ms=int(now_ms),
                track_peer=bool(welcome.accepted),
            )
            # Publish lobby state update after accepting/rejecting.
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
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
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, Disconnect):
            lan_debug_log("net_recv", role="host", kind="disconnect", addr=f"{addr[0]}:{addr[1]}")
            slot = lobby.slot_for_addr(addr)
            self.host_peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            if slot is not None:
                self._host_seen_input_slots.discard(int(slot))
            if bool(lobby.started):
                self._abort_host_match(reason="peer_disconnect", now_ms=int(now_ms), addr=addr)
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, DebugLogBatch):
            mapped_slot = lobby.slot_for_addr(addr)
            msg_slot = int(message.slot_index)
            slot_index = int(mapped_slot) if mapped_slot is not None else int(msg_slot)
            if int(slot_index) <= 0:
                return
            lines = list(message.lines)
            self._host_write_remote_log_batch(addr=addr, slot_index=int(slot_index), lines=lines)
            return
        if isinstance(message, InputBatch):
            lockstep = self.host_lockstep
            if lockstep is None:
                return
            mapped_slot = lobby.slot_for_addr(addr)
            if mapped_slot is None:
                return
            if int(mapped_slot) > 0:
                self._host_seen_input_slots.add(int(mapped_slot))
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
            lockstep.submit_input_batch(batch)
            return

    def _host_send(
        self,
        addr: PeerAddr,
        message: NetMessage,
        *,
        reliable: bool,
        now_ms: int,
        track_peer: bool = True,
    ) -> None:
        peer = self.host_peers.get(addr)
        if peer is None and bool(track_peer):
            peer = _HostPeerLink(addr=addr, last_seen_ms=int(now_ms))
            self.host_peers[addr] = peer
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
        kind = type(message).__name__
        lan_debug_log(
            "net_send",
            role="host",
            kind=kind,
            addr=f"{addr[0]}:{addr[1]}",
            reliable=bool(reliable),
        )

    def _host_broadcast(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        for addr in list(self.host_peers):
            self._host_send(addr, message, reliable=bool(reliable), now_ms=int(now_ms))

    def _host_broadcast_lobby_state(self, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return
        state = lobby.lobby_state()
        self._host_broadcast(state, reliable=True, now_ms=int(now_ms))

    def _update_client(self, *, now_ms: int) -> None:
        lobby = self.client_lobby
        link = self.client_link
        host = self.client_host_addr
        if lobby is None or link is None or host is None:
            return
        if self.error:
            return

        # Send hello until welcome arrives.
        if (
            lobby.welcome is None
            and int(link.pending_count) <= 0
            and (int(now_ms) - int(self.client_last_hello_ms)) >= 200
        ):
            self.client_last_hello_ms = int(now_ms)
            self._client_send(lobby.hello, reliable=True, now_ms=int(now_ms))

        for addr, packet in self.transport.recv_packets(max_packets=int(MAX_RECV_PACKETS_PER_UPDATE)):
            if addr != host:
                continue
            self.client_last_seen_ms = int(now_ms)
            messages, dup = link.ingest_packet(packet, now_ms=int(now_ms))
            if dup:
                lan_debug_log("net_recv_dup", role="join", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_client_message(message, now_ms=int(now_ms))
                if self.error:
                    return

        timeout_ms = int(LINK_TIMEOUT_MS)
        if bool(self.started) and (not bool(self._client_seen_tick_frame)):
            timeout_ms = int(LOADING_LINK_TIMEOUT_MS)
        pause_state = self.client_pause_state
        if (
            bool(self.started)
            and pause_state is not None
            and bool(pause_state.paused)
            and str(pause_state.reason or "") == "waiting_input"
        ):
            timeout_ms = max(int(timeout_ms), int(PAUSED_LINK_TIMEOUT_MS))
        if (int(now_ms) - int(self.client_last_seen_ms)) >= int(timeout_ms):
            if not self.error:
                self._set_client_error("timeout")
                lan_debug_log(
                    "net_timeout",
                    role="join",
                    addr=f"{host[0]}:{host[1]}",
                    timeout_ms=int(timeout_ms),
                    started=bool(self.started),
                    seen_tick_frame=bool(self._client_seen_tick_frame),
                )
            return

        self._client_flush_forwarded_logs(now_ms=int(now_ms))

        for resend in link.poll_resends(now_ms=int(now_ms)):
            try:
                self.transport.send_packet(host, resend)
            except OSError:
                continue
            self._last_send_ms = int(now_ms)
            self._client_last_send_ms = int(now_ms)

        # Prevent timeouts during stalls/pauses by sending best-effort keepalives.
        if bool(self.started):
            last_send = int(self._last_send_ms)
            if last_send <= 0:
                self._last_send_ms = int(now_ms)
            elif (int(now_ms) - int(last_send)) >= int(KEEPALIVE_INTERVAL_MS):
                tick_index = 0
                if self.client_lockstep is not None:
                    tick_index = int(self.client_lockstep.next_consume_tick)
                self._client_send(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

        self._client_send_idle_heartbeat(now_ms=int(now_ms))

    def _handle_client_message(self, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.client_lobby
        if lobby is None:
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
            lobby.ingest_welcome(message)
            if not bool(message.accepted):
                self._set_client_error(str(message.reason or "rejected"))
                return
            welcome_settings = session_settings_from_welcome(message)
            hello = lobby.hello
            if hello is not None:
                hello_settings = session_settings_from_hello(hello)
                mismatched = hello_settings != welcome_settings
                if mismatched:
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

            # Host is authoritative; adopt its config so lockstep + validation use
            # canonical values (CLI joiners may start with placeholders).
            self.cfg.mode_id = welcome_settings.mode_id
            self.cfg.player_count = int(welcome_settings.player_count)
            self.cfg.tick_rate = int(welcome_settings.tick_rate)
            self.cfg.input_delay_ticks = int(welcome_settings.input_delay_ticks)
            self.cfg.quest_level = welcome_settings.quest_level
            self.cfg.preserve_bugs = bool(welcome_settings.preserve_bugs)
            ready = Ready(slot_index=int(message.slot_index), ready=True)
            self._client_send(ready, reliable=True, now_ms=int(now_ms))
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
            lobby.ingest_lobby_state(message)
            return
        if isinstance(message, MatchStart):
            status = message.status
            status_unlock = 0
            status_unlock_full = 0
            if status is not None:
                status_unlock = int(status.quest_unlock_index)
                status_unlock_full = int(status.quest_unlock_index_full)
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
            welcome = lobby.welcome
            if (
                welcome is not None
                and str(welcome.session_id or "")
                and str(message.session_id or "") != str(welcome.session_id or "")
            ):
                self._set_client_error("session_id_mismatch")
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
            mismatched = match_settings != expected_settings
            if mismatched:
                self._set_client_error("match_start_mismatch")
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

            status = message.status
            if status is None:
                self._set_client_error("match_start_missing_status")
                lan_debug_log(
                    "net_sanity_error",
                    role="join",
                    kind="match_start",
                    reason=str(self.error),
                )
                return

            lobby.ingest_match_start(message)
            self.started = True
            self._client_init_lockstep(message)
            return
        if isinstance(message, TickFrame):
            self._client_seen_tick_frame = True
            lockstep = self.client_lockstep
            if lockstep is None:
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
                lan_debug_log(
                    "net_recv",
                    role="join",
                    kind="tick_frame",
                    tick_index=int(tick),
                    command_count=len(message.commands),
                )
            lockstep.ingest_tick_frame(message, now_ms=int(now_ms))
            queued_at = self._client_input_queued_at_ms.pop(int(tick), None)
            if queued_at is not None:
                latency_ms = max(0, int(now_ms) - int(queued_at))
                self._client_local_input_latency_ms = int(latency_ms)
                if self._client_local_input_latency_ewma_ms <= 0.0:
                    self._client_local_input_latency_ewma_ms = float(latency_ms)
                else:
                    self._client_local_input_latency_ewma_ms = float(
                        self._client_local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1,
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
            # Lobby doesn't model pause; keep for logging and future integration.
            self.client_pause_state = message
            return
        if isinstance(message, Disconnect):
            lan_debug_log("net_recv", role="join", kind="disconnect", reason=str(message.reason or ""))
            self._set_client_error(str(message.reason or "disconnect"))
            return
        lan_debug_log("net_recv", role="join", kind=type(message).__name__)

    def _client_send(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        link = self.client_link
        host = self.client_host_addr
        if link is None or host is None:
            return
        packet = link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(host, packet)
        except OSError:
            return
        self._last_send_ms = int(now_ms)
        self._client_last_send_ms = int(now_ms)
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, DebugLogBatch):
            # Avoid recursive log forwarding (sending logs would itself get logged).
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

    def _client_send_idle_heartbeat(self, *, now_ms: int) -> None:
        if not bool(self.started):
            return
        pause_state = self.client_pause_state
        if (
            pause_state is None
            or (not bool(pause_state.paused))
            or str(pause_state.reason or "") != "waiting_input"
        ):
            return
        if (int(now_ms) - int(self._client_last_send_ms)) < int(IDLE_HEARTBEAT_MS):
            return
        lobby = self.client_lobby
        link = self.client_link
        if lobby is None or link is None:
            return
        if int(link.pending_count) > 0:
            return
        self._client_send(
            InputBatch(slot_index=int(lobby.slot_index), samples=[]),
            reliable=False,
            now_ms=int(now_ms),
        )

    def _trace_metrics(self, *, now_ms: int) -> None:
        if (int(now_ms) - int(self._metrics_last_log_ms)) < 1000:
            return
        self._metrics_last_log_ms = int(now_ms)

        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = ftol_ms_i32(float(delay_ticks) * 1000.0 / float(tick_rate))

        role = str(self.cfg.role)
        if role == "host":
            lockstep = self.host_lockstep
            waiting_for = int(lockstep.waiting_for_inputs()) if lockstep is not None else 0
            stall_ms = 0
            if lockstep is not None and waiting_for > 0:
                stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))

            capture_tick = int(self.host_capture_tick)
            emit_tick = int(lockstep.next_emit_tick) if lockstep is not None else 0
            ready_frames = len(self.host_ready_ticks)
            buffered_ticks = int(lockstep.buffered_tick_count) if lockstep is not None else 0
            target_lead_ticks = int(capture_tick) + int(delay_ticks) - int(emit_tick)

            rtts = [int(peer.link.rtt_last_ms) for peer in self.host_peers.values() if peer.link.rtt_last_ms > 0]
            rtt_min = min(rtts) if rtts else 0
            rtt_max = max(rtts) if rtts else 0
            pending_max = max((int(peer.link.pending_count) for peer in self.host_peers.values()), default=0)
            resends_total = sum(int(peer.link.resend_count) for peer in self.host_peers.values())
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
                input_latency_ms=int(self._host_local_input_latency_ms),
                input_latency_ewma_ms=int(self._host_local_input_latency_ewma_ms),
            )
            return

        link = self.client_link
        lockstep = self.client_lockstep
        pending = int(link.pending_count) if link is not None else 0
        resends_total = int(link.resend_count) if link is not None else 0
        resends_delta = max(0, int(resends_total) - int(self._metrics_last_resends_total))
        self._metrics_last_resends_total = int(resends_total)

        stall_ms = 0
        if lockstep is not None and int(lockstep.buffered_frame_count) <= 0:
            stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))

        capture_tick = int(lockstep.capture_tick) if lockstep is not None else 0
        consume_tick = int(lockstep.next_consume_tick) if lockstep is not None else 0
        buffered_frames = int(lockstep.buffered_frame_count) if lockstep is not None else 0
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
            rtt_ms=int(link.rtt_last_ms) if link is not None else 0,
            rtt_ewma_ms=int(link.rtt_ewma_ms) if link is not None else 0,
            pending=int(pending),
            resends_s=int(resends_delta),
            input_latency_ms=int(self._client_local_input_latency_ms),
            input_latency_ewma_ms=int(self._client_local_input_latency_ewma_ms),
        )

    def _host_init_lockstep(self, event: MatchStart) -> None:
        player_count = max(1, min(4, int(event.player_count)))
        self.host_lockstep = HostLockstepState(
            player_count=int(player_count),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.host_capture_tick = 0
        self.host_ready_ticks.clear()
        self._pending_host_commands.clear()

        # Prime initial ticks (0..delay-1) with neutral inputs so the match can start immediately.
        delay = max(0, int(self.cfg.input_delay_ticks))
        neutral = list(self._neutral_input)
        for tick in range(int(delay)):
            for slot in range(int(player_count)):
                self.host_lockstep.submit_input_sample(
                    slot_index=int(slot),
                    tick_index=int(tick),
                    packed_input=list(neutral),
                )

    def _client_init_lockstep(self, event: MatchStart) -> None:
        slot_index = int(self.local_slot_index)
        self.client_lockstep = ClientLockstepState(
            local_slot_index=int(slot_index),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.client_pause_state = None
        self._client_seen_tick_frame = False


__all__ = [
    "HostLockstepRuntimeConfig",
    "JoinLockstepRuntimeConfig",
    "LockstepRuntime",
    "LockstepRuntimeConfig",
]
