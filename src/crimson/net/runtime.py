from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import datetime as dt
from pathlib import Path
import socket
import time

from .debug_log import lan_debug_log, lan_debug_log_path, set_lan_debug_forwarder
from .deterministic_status import hash_status_snapshot
from .lobby import ClientLobby, HostLobby
from .lockstep import ClientLockstepState, HostLockstepState
from .protocol import (
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    TICK_RATE,
    DebugLogBatch,
    DesyncNotice,
    Disconnect,
    Hello,
    KeepAlive,
    InputBatch,
    LobbyState,
    MatchStart,
    NetMessage,
    PauseState,
    PerkMenuOpen,
    PerkMenuClose,
    PerkPick,
    Ready,
    StatusSnapshot,
    TickFrame,
    Welcome,
    current_build_id,
)
from .reliable import ReliableLink
from .transport import PeerAddr, UdpTransport
from ..replay.types import PackedPlayerInput


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

# Bound socket drain work per update to avoid frame-time spikes under burst traffic.
MAX_RECV_PACKETS_PER_UPDATE = 512


@dataclass(slots=True)
class LanRuntimeConfig:
    role: str
    mode_id: int
    player_count: int
    bind_host: str
    host_ip: str
    port: int
    quest_level: str = ""
    preserve_bugs: bool = False
    tick_rate: int = TICK_RATE
    input_delay_ticks: int = INPUT_DELAY_TICKS
    sim_status_snapshot: StatusSnapshot | None = None


@dataclass(slots=True)
class _HostPeerLink:
    addr: PeerAddr
    link: ReliableLink = field(default_factory=ReliableLink)
    last_seen_ms: int = 0


@dataclass(slots=True)
class LanRuntime:
    """Drive LAN lobby handshake and keep socket state alive across views."""

    cfg: LanRuntimeConfig
    build_id: str = field(default_factory=current_build_id)
    transport: UdpTransport = field(init=False)
    started: bool = field(init=False, default=False)
    error: str = field(init=False, default="")

    host_lobby: HostLobby | None = field(init=False, default=None)
    host_peers: dict[PeerAddr, _HostPeerLink] = field(init=False, default_factory=dict)
    host_seed: int = field(init=False, default=0)
    host_match_start: MatchStart | None = field(init=False, default=None)
    host_last_broadcast_ms: int = field(init=False, default=0)
    host_lockstep: HostLockstepState | None = field(init=False, default=None)
    host_capture_tick: int = field(init=False, default=0)
    host_ready_frames: deque[TickFrame] = field(init=False, default_factory=deque)
    _host_seen_input_slots: set[int] = field(init=False, default_factory=set)

    client_lobby: ClientLobby | None = field(init=False, default=None)
    client_link: ReliableLink | None = field(init=False, default=None)
    client_host_addr: PeerAddr | None = field(init=False, default=None)
    client_last_hello_ms: int = field(init=False, default=0)
    client_last_seen_ms: int = field(init=False, default=0)
    client_lockstep: ClientLockstepState | None = field(init=False, default=None)
    client_pause_state: PauseState | None = field(init=False, default=None)
    _client_seen_tick_frame: bool = field(init=False, default=False)
    _last_send_ms: int = field(init=False, default=0)

    _client_perk_events: deque[PerkMenuOpen | PerkMenuClose | PerkPick] = field(init=False, default_factory=deque)

    # Instrumentation (debug overlay + lan debug logs).
    _metrics_last_log_ms: int = field(init=False, default=0)
    _metrics_last_resends_total: int = field(init=False, default=0)

    _host_input_queued_at_ms: dict[int, int] = field(init=False, default_factory=dict)
    _host_local_input_latency_ms: int = field(init=False, default=0)
    _host_local_input_latency_ewma_ms: float = field(init=False, default=0.0)

    _client_input_queued_at_ms: dict[int, int] = field(init=False, default_factory=dict)
    _client_local_input_latency_ms: int = field(init=False, default=0)
    _client_local_input_latency_ewma_ms: float = field(init=False, default=0.0)

    desync_count: int = field(init=False, default=0)
    last_desync_tick: int = field(init=False, default=-1)
    last_desync_kind: str = field(init=False, default="")
    last_desync_expected: str = field(init=False, default="")
    last_desync_actual: str = field(init=False, default="")
    _last_desync_notice_sent_tick: int = field(init=False, default=-10**9)

    _client_log_forward_queue: deque[str] = field(init=False, default_factory=deque)
    _client_log_forward_last_flush_ms: int = field(init=False, default=0)
    _client_log_forward_dropped: int = field(init=False, default=0)
    _client_log_forward_enabled: bool = field(init=False, default=False)

    _host_remote_log_paths: dict[int, Path] = field(init=False, default_factory=dict)

    _neutral_input: PackedPlayerInput = field(
        init=False,
        default_factory=lambda: [0.0, 0.0, [0.0, 0.0], 0],
    )

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
        self._last_desync_notice_sent_tick = -10**9
        self._client_log_forward_queue.clear()
        self._client_log_forward_last_flush_ms = 0
        self._client_log_forward_dropped = 0
        self._client_log_forward_enabled = False
        self._host_remote_log_paths.clear()
        self._client_seen_tick_frame = False
        self._client_perk_events.clear()
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
                mode_id=int(self.cfg.mode_id),
                player_count=int(self.cfg.player_count),
                build_id=str(self.build_id),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
                quest_level=str(self.cfg.quest_level),
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
            hello = Hello(
                protocol_version=int(PROTOCOL_VERSION),
                build_id=str(self.build_id),
                mode_id=int(self.cfg.mode_id),
                player_count=int(self.cfg.player_count),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
                quest_level=str(self.cfg.quest_level),
                preserve_bugs=bool(self.cfg.preserve_bugs),
                host=False,
            )
            self.client_lobby = ClientLobby(build_id=str(self.build_id), hello=hello)
            self.client_last_hello_ms = 0
            self.client_last_seen_ms = _now_ms()

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
            self.host_lockstep = None
            self.host_capture_tick = 0
            self.host_ready_frames.clear()
            self.client_lockstep = None
            self.client_pause_state = None
            self._last_send_ms = 0
            self._client_perk_events.clear()
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
            self._last_desync_notice_sent_tick = -10**9
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
        """Return short debug HUD lines for in-game overlays (guarded by --debug)."""
        lines: list[str] = []
        role = str(self.cfg.role)
        now_ms = _now_ms()
        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = int(round(float(delay_ticks) * 1000.0 / float(tick_rate)))

        if self.error:
            lines.append(f"net: error={self.error}")
        if int(self.desync_count) > 0:
            exp = str(self.last_desync_expected or "")[:8]
            act = str(self.last_desync_actual or "")[:8]
            lines.append(
                "desyncs: "
                f"{int(self.desync_count)} "
                f"last={str(self.last_desync_kind or '?')}@{int(self.last_desync_tick)} "
                f"{exp}!={act}"
            )

        if role == "host":
            lines.append(
                "net(host): "
                f"bind={self.cfg.bind_host}:{self.bound_port} "
                f"peers={len(self.host_peers)}/{max(0, int(self.cfg.player_count) - 1)} "
                f"started={int(self.started)}"
            )
            lockstep = self.host_lockstep
            if lockstep is not None:
                waiting_for = int(lockstep.waiting_for_inputs())
                stall_ms = 0
                if waiting_for > 0:
                    stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))
                target_lead = int(self.host_capture_tick) + int(delay_ticks) - int(lockstep.next_emit_tick)
                lines.append(
                    "lockstep(host): "
                    f"capture={int(self.host_capture_tick)} "
                    f"emit={int(lockstep.next_emit_tick)} "
                    f"target_lead={int(target_lead)} "
                    f"ready_frames={len(self.host_ready_frames)} "
                    f"buffered_ticks={int(lockstep.buffered_tick_count)} "
                    f"waiting_for={int(waiting_for)} "
                    f"paused={int(lockstep.paused)} "
                    f"stall_ms={int(stall_ms)}"
                )
                rtts = [int(peer.link.rtt_last_ms) for peer in self.host_peers.values() if peer.link.rtt_last_ms > 0]
                rtt_label = "?"
                if rtts:
                    rtt_label = f"{min(rtts)}..{max(rtts)}"
                pending_max = max((int(peer.link.pending_count) for peer in self.host_peers.values()), default=0)
                resends_total = sum(int(peer.link.resend_count) for peer in self.host_peers.values())
                input_ms = int(self._host_local_input_latency_ms)
                input_ewma_ms = int(self._host_local_input_latency_ewma_ms)
                lines.append(
                    "lat(host): "
                    f"delay={delay_ticks}t({delay_ms}ms) "
                    f"input_ms={input_ms}/{input_ewma_ms} "
                    f"rtt_ms={rtt_label} "
                    f"pending={pending_max} "
                    f"resends={resends_total}"
                )
            return lines

        lobby = self.client_lobby
        host = self.client_host_addr
        host_label = f"{host[0]}:{host[1]}" if host is not None else "?"
        joined = bool(lobby.joined) if lobby is not None else False
        started = bool(lobby.started) if lobby is not None else False
        slot = int(lobby.slot_index) if lobby is not None else -1
        lines.append(
            "net(join): "
            f"host={host_label} local_port={self.bound_port} slot={slot} joined={int(joined)} started={int(started)}"
        )

        lockstep = self.client_lockstep
        if lockstep is not None:
            stall_ms = 0
            if int(lockstep.buffered_frame_count) <= 0:
                stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))
            lines.append(
                "lockstep(join): "
                f"capture={int(lockstep.capture_tick)} "
                f"consume={int(lockstep.next_consume_tick)} "
                f"buffered_frames={int(lockstep.buffered_frame_count)} "
                f"paused={int(lockstep.paused)} "
                f"stall_ms={int(stall_ms)}"
            )
        link = self.client_link
        if link is not None:
            input_ms = int(self._client_local_input_latency_ms)
            input_ewma_ms = int(self._client_local_input_latency_ewma_ms)
            lines.append(
                "lat(join): "
                f"delay={delay_ticks}t({delay_ms}ms) "
                f"input_ms={input_ms}/{input_ewma_ms} "
                f"rtt_ms={int(link.rtt_last_ms)}/{int(link.rtt_ewma_ms)} "
                f"pending={int(link.pending_count)} "
                f"resends={int(link.resend_count)}"
            )
        pause = self.client_pause_state
        if pause is not None and bool(pause.paused):
            lines.append(f"pause: {str(pause.reason or '')}")

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

        # Best-effort: send a notice to the host so both logs can be correlated.
        if str(self.cfg.role) != "join":
            return
        if str(kind) != "command_hash":
            return
        if (int(tick_index) - int(self._last_desync_notice_sent_tick)) < 60:
            return
        self._last_desync_notice_sent_tick = int(tick_index)
        try:
            self._client_send(
                DesyncNotice(
                    tick_index=int(tick_index),
                    expected_command_hash=str(expected),
                    actual_command_hash=str(actual),
                ),
                reliable=True,
                now_ms=_now_ms(),
            )
        except Exception:
            return

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
        welcome = getattr(lobby, "welcome", None)
        if welcome is None or not bool(getattr(welcome, "accepted", False)):
            return
        slot_index = int(getattr(welcome, "slot_index", -1) or -1)
        if int(slot_index) <= 0:
            return

        lines: list[str] = []
        chars = 0
        dropped = int(self._client_log_forward_dropped)
        if dropped > 0:
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
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
        except Exception:
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
            timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            path = host_path.parent / f"lan-client-slot{int(slot_index)}-from{safe_ip}-{int(addr[1])}-{timestamp}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            session_id = ""
            lobby = self.host_lobby
            if lobby is not None:
                session_id = str(getattr(lobby, "session_id", "") or "")
            init_ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
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

    def pop_perk_event(self) -> PerkMenuOpen | PerkMenuClose | PerkPick | None:
        if not self._client_perk_events:
            return None
        return self._client_perk_events.popleft()

    def pop_tick_frame(self) -> TickFrame | None:
        if str(self.cfg.role) == "host":
            if not self.host_ready_frames:
                return None
            return self.host_ready_frames.popleft()
        lockstep = self.client_lockstep
        if lockstep is None:
            return None
        return lockstep.pop_canonical_frame()

    def broadcast_tick_frame(self, frame: TickFrame, *, now_ms: int | None = None) -> None:
        if str(self.cfg.role) != "host":
            return
        if now_ms is None:
            now_ms = _now_ms()
        self._host_broadcast(frame, reliable=True, now_ms=int(now_ms))

    def broadcast_perk_menu_open(self, *, tick_index: int, player_index: int = 0, now_ms: int | None = None) -> None:
        if str(self.cfg.role) != "host":
            return
        if now_ms is None:
            now_ms = _now_ms()
        self._host_broadcast(
            PerkMenuOpen(tick_index=int(tick_index), player_index=int(player_index)),
            reliable=True,
            now_ms=int(now_ms),
        )

    def broadcast_perk_menu_close(self, *, tick_index: int, player_index: int = 0, now_ms: int | None = None) -> None:
        if str(self.cfg.role) != "host":
            return
        if now_ms is None:
            now_ms = _now_ms()
        self._host_broadcast(
            PerkMenuClose(tick_index=int(tick_index), player_index=int(player_index)),
            reliable=True,
            now_ms=int(now_ms),
        )

    def broadcast_perk_pick(
        self,
        *,
        tick_index: int,
        player_index: int = 0,
        choice_index: int,
        now_ms: int | None = None,
    ) -> None:
        if str(self.cfg.role) != "host":
            return
        if now_ms is None:
            now_ms = _now_ms()
        self._host_broadcast(
            PerkPick(tick_index=int(tick_index), player_index=int(player_index), choice_index=int(choice_index)),
            reliable=True,
            now_ms=int(now_ms),
        )

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
                message = getattr(packet, "message", None)
                if isinstance(message, Hello):
                    self._handle_host_message(addr, message, now_ms=int(now_ms))
                    accepted_peer = self.host_peers.get(addr)
                    if (
                        accepted_peer is not None
                        and bool(getattr(packet, "reliable", False))
                        and int(getattr(packet, "seq", 0) or 0) > 0
                    ):
                        accepted_peer.link.prime_recv_seq(int(getattr(packet, "seq", 0) or 0))
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
            status_snapshot = self.cfg.sim_status_snapshot
            if status_snapshot is None:
                self.error = "missing_sim_status_snapshot"
                lan_debug_log(
                    "net_sanity_error",
                    role="host",
                    kind="match_start",
                    reason=str(self.error),
                )
                return
            status_hash = hash_status_snapshot(status_snapshot)
            self.host_seed = int((_now_ms() * 1103515245 + 12345) & 0xFFFFFFFF)
            event = lobby.start_match(
                seed=int(self.host_seed),
                status_snapshot=status_snapshot,
                status_hash=str(status_hash),
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
                status_hash=str(status_hash),
                status_quest_unlock_index=int(status_snapshot.quest_unlock_index),
                status_quest_unlock_index_full=int(status_snapshot.quest_unlock_index_full),
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
                tick = int(getattr(frame, "tick_index", 0) or 0)
                queued_at = self._host_input_queued_at_ms.pop(int(tick), None)
                if queued_at is not None:
                    latency_ms = max(0, int(now_ms) - int(queued_at))
                    self._host_local_input_latency_ms = int(latency_ms)
                    if self._host_local_input_latency_ewma_ms <= 0.0:
                        self._host_local_input_latency_ewma_ms = float(latency_ms)
                    else:
                        self._host_local_input_latency_ewma_ms = float(
                            self._host_local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1
                        )
                self.host_ready_frames.append(frame)

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
                    tick_index = int(getattr(self.host_lockstep, "next_emit_tick", 0) or 0)
                self._host_broadcast(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

    def _handle_host_message(self, addr: PeerAddr, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, PerkMenuOpen) or isinstance(message, PerkMenuClose) or isinstance(message, PerkPick):
            # Host is authoritative for perk events; ignore unexpected client packets.
            return
        if isinstance(message, Hello):
            lan_debug_log(
                "net_recv",
                role="host",
                kind="hello",
                addr=f"{addr[0]}:{addr[1]}",
                protocol_version=int(getattr(message, "protocol_version", 0) or 0),
                build_id=str(getattr(message, "build_id", "") or ""),
                mode_id=int(getattr(message, "mode_id", 0) or 0),
                player_count=int(getattr(message, "player_count", 1) or 1),
                tick_rate=int(getattr(message, "tick_rate", 0) or 0),
                input_delay_ticks=int(getattr(message, "input_delay_ticks", 0) or 0),
                quest_level=str(getattr(message, "quest_level", "") or ""),
                preserve_bugs=bool(getattr(message, "preserve_bugs", False)),
                host=bool(getattr(message, "host", False)),
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
        if isinstance(message, DesyncNotice):
            lan_debug_log(
                "net_recv",
                role="host",
                kind="desync_notice",
                addr=f"{addr[0]}:{addr[1]}",
                tick_index=int(message.tick_index),
                expected_command_hash=str(message.expected_command_hash or ""),
                actual_command_hash=str(message.actual_command_hash or ""),
            )
            self.note_desync(
                kind="command_hash",
                tick_index=int(message.tick_index),
                expected=str(message.expected_command_hash or ""),
                actual=str(message.actual_command_hash or ""),
            )
            return
        if isinstance(message, DebugLogBatch):
            mapped_slot = lobby.slot_for_addr(addr)
            msg_slot = int(getattr(message, "slot_index", -1) or -1)
            slot_index = int(mapped_slot) if mapped_slot is not None else int(msg_slot)
            if int(slot_index) <= 0:
                return
            lines = list(getattr(message, "lines", []) or [])
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
                tick = int(getattr(sample, "tick_index", 0) or 0)
                max_tick = max(int(max_tick), int(tick))
                min_tick = min(int(min_tick), int(tick))
            if max_tick >= 0 and (int(max_tick) < 5 or (int(max_tick) % 60) == 0):
                lan_debug_log(
                    "net_recv",
                    role="host",
                    kind="input_batch",
                    addr=f"{addr[0]}:{addr[1]}",
                    slot_index=int(batch.slot_index),
                    sample_count=int(len(batch.samples)),
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
        if peer is None:
            if bool(track_peer):
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
            tick = int(getattr(message, "tick_index", 0) or 0)
            if int(tick) < 5 or (int(tick) % 60) == 0:
                lan_debug_log(
                    "net_send",
                    role="host",
                    kind="tick_frame",
                    addr=f"{addr[0]}:{addr[1]}",
                    reliable=bool(reliable),
                    tick_index=int(tick),
                    command_hash=str(getattr(message, "command_hash", "") or ""),
                    state_hash=str(getattr(message, "state_hash", "") or ""),
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
        if isinstance(message, PerkMenuOpen):
            lan_debug_log(
                "net_send",
                role="host",
                kind="perk_menu_open",
                addr=f"{addr[0]}:{addr[1]}",
                reliable=bool(reliable),
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
            )
            return
        if isinstance(message, PerkMenuClose):
            lan_debug_log(
                "net_send",
                role="host",
                kind="perk_menu_close",
                addr=f"{addr[0]}:{addr[1]}",
                reliable=bool(reliable),
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
            )
            return
        if isinstance(message, PerkPick):
            lan_debug_log(
                "net_send",
                role="host",
                kind="perk_pick",
                addr=f"{addr[0]}:{addr[1]}",
                reliable=bool(reliable),
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
                choice_index=int(message.choice_index),
            )
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log(
            "net_send",
            role="host",
            kind=str(kind),
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

        # Prevent timeouts during stalls/pauses by sending best-effort keepalives.
        if bool(self.started):
            last_send = int(self._last_send_ms)
            if last_send <= 0:
                self._last_send_ms = int(now_ms)
            elif (int(now_ms) - int(last_send)) >= int(KEEPALIVE_INTERVAL_MS):
                tick_index = 0
                if self.client_lockstep is not None:
                    tick_index = int(getattr(self.client_lockstep, "next_consume_tick", 0) or 0)
                self._client_send(KeepAlive(tick_index=int(tick_index)), reliable=False, now_ms=int(now_ms))

    def _handle_client_message(self, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.client_lobby
        if lobby is None:
            return
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, PerkMenuOpen):
            lan_debug_log(
                "net_recv",
                role="join",
                kind="perk_menu_open",
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
            )
            self._client_perk_events.append(message)
            return
        if isinstance(message, PerkMenuClose):
            lan_debug_log(
                "net_recv",
                role="join",
                kind="perk_menu_close",
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
            )
            self._client_perk_events.append(message)
            return
        if isinstance(message, PerkPick):
            lan_debug_log(
                "net_recv",
                role="join",
                kind="perk_pick",
                tick_index=int(message.tick_index),
                player_index=int(message.player_index),
                choice_index=int(message.choice_index),
            )
            self._client_perk_events.append(message)
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
                protocol_version=int(getattr(message, "protocol_version", 0) or 0),
                build_id=str(getattr(message, "build_id", "") or ""),
                mode_id=int(getattr(message, "mode_id", 0) or 0),
                player_count=int(getattr(message, "player_count", 1) or 1),
                tick_rate=int(getattr(message, "tick_rate", 0) or 0),
                input_delay_ticks=int(getattr(message, "input_delay_ticks", 0) or 0),
                quest_level=str(getattr(message, "quest_level", "") or ""),
                preserve_bugs=bool(getattr(message, "preserve_bugs", False)),
                started=bool(getattr(message, "started", False)),
            )
            lobby.ingest_welcome(message)
            if not bool(message.accepted):
                self._set_client_error(str(message.reason or "rejected"))
                return
            hello = getattr(lobby, "hello", None)
            if hello is not None:
                mismatched = (
                    int(getattr(message, "mode_id", 0) or 0) != int(getattr(hello, "mode_id", 0) or 0)
                    or int(getattr(message, "player_count", 1) or 1) != int(getattr(hello, "player_count", 1) or 1)
                    or int(getattr(message, "tick_rate", 0) or 0) != int(getattr(hello, "tick_rate", 0) or 0)
                    or int(getattr(message, "input_delay_ticks", 0) or 0)
                    != int(getattr(hello, "input_delay_ticks", 0) or 0)
                    or str(getattr(message, "quest_level", "") or "") != str(getattr(hello, "quest_level", "") or "")
                    or bool(getattr(message, "preserve_bugs", False)) != bool(getattr(hello, "preserve_bugs", False))
                )
                if mismatched:
                    lan_debug_log(
                        "net_welcome_override",
                        role="join",
                        hello_mode_id=int(getattr(hello, "mode_id", 0) or 0),
                        welcome_mode_id=int(getattr(message, "mode_id", 0) or 0),
                        hello_player_count=int(getattr(hello, "player_count", 1) or 1),
                        welcome_player_count=int(getattr(message, "player_count", 1) or 1),
                        hello_tick_rate=int(getattr(hello, "tick_rate", 0) or 0),
                        welcome_tick_rate=int(getattr(message, "tick_rate", 0) or 0),
                        hello_input_delay_ticks=int(getattr(hello, "input_delay_ticks", 0) or 0),
                        welcome_input_delay_ticks=int(getattr(message, "input_delay_ticks", 0) or 0),
                        hello_quest_level=str(getattr(hello, "quest_level", "") or ""),
                        welcome_quest_level=str(getattr(message, "quest_level", "") or ""),
                        hello_preserve_bugs=bool(getattr(hello, "preserve_bugs", False)),
                        welcome_preserve_bugs=bool(getattr(message, "preserve_bugs", False)),
                    )

            # Host is authoritative; adopt its config so lockstep + validation use
            # canonical values (CLI joiners may start with placeholders).
            self.cfg.mode_id = int(getattr(message, "mode_id", 0) or 0)
            self.cfg.player_count = max(1, min(4, int(getattr(message, "player_count", 1) or 1)))
            self.cfg.tick_rate = max(1, int(getattr(message, "tick_rate", 0) or 0))
            self.cfg.input_delay_ticks = max(0, int(getattr(message, "input_delay_ticks", 0) or 0))
            self.cfg.quest_level = str(getattr(message, "quest_level", "") or "")
            self.cfg.preserve_bugs = bool(getattr(message, "preserve_bugs", False))
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
            status_snapshot = message.status_snapshot
            status_unlock = 0
            status_unlock_full = 0
            if status_snapshot is not None:
                status_unlock = int(status_snapshot.quest_unlock_index)
                status_unlock_full = int(status_snapshot.quest_unlock_index_full)
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
                status_hash=str(message.status_hash or ""),
                status_quest_unlock_index=int(status_unlock),
                status_quest_unlock_index_full=int(status_unlock_full),
            )
            welcome = getattr(lobby, "welcome", None)
            if welcome is not None and str(getattr(welcome, "session_id", "") or ""):
                if str(getattr(message, "session_id", "") or "") != str(getattr(welcome, "session_id", "") or ""):
                    self._set_client_error("session_id_mismatch")
                    lan_debug_log(
                        "net_sanity_mismatch",
                        role="join",
                        kind="match_start",
                        expected_session_id=str(getattr(welcome, "session_id", "") or ""),
                        actual_session_id=str(getattr(message, "session_id", "") or ""),
                    )
                    return
            mismatched = (
                int(getattr(message, "mode_id", 0) or 0) != int(self.cfg.mode_id)
                or int(getattr(message, "player_count", 1) or 1) != int(self.cfg.player_count)
                or str(getattr(message, "quest_level", "") or "") != str(self.cfg.quest_level or "")
                or bool(getattr(message, "preserve_bugs", False)) != bool(self.cfg.preserve_bugs)
            )
            if mismatched:
                self._set_client_error("match_start_mismatch")
                lan_debug_log(
                    "net_sanity_mismatch",
                    role="join",
                    kind="match_start",
                    expected_mode_id=int(self.cfg.mode_id),
                    actual_mode_id=int(getattr(message, "mode_id", 0) or 0),
                    expected_player_count=int(self.cfg.player_count),
                    actual_player_count=int(getattr(message, "player_count", 1) or 1),
                    expected_quest_level=str(self.cfg.quest_level or ""),
                    actual_quest_level=str(getattr(message, "quest_level", "") or ""),
                    expected_preserve_bugs=bool(self.cfg.preserve_bugs),
                    actual_preserve_bugs=bool(getattr(message, "preserve_bugs", False)),
                )
                return

            status_snapshot = message.status_snapshot
            if status_snapshot is None:
                self._set_client_error("match_start_missing_status_snapshot")
                lan_debug_log(
                    "net_sanity_error",
                    role="join",
                    kind="match_start",
                    reason=str(self.error),
                )
                return
            expected_hash = str(getattr(message, "status_hash", "") or "")
            if expected_hash:
                actual_hash = hash_status_snapshot(status_snapshot)
                if str(actual_hash) != str(expected_hash):
                    self._set_client_error("match_start_status_hash_mismatch")
                    lan_debug_log(
                        "net_sanity_mismatch",
                        role="join",
                        kind="match_start_status_hash",
                        expected=str(expected_hash),
                        actual=str(actual_hash),
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
            tick = int(getattr(message, "tick_index", 0) or 0)
            if int(tick) < 0:
                lan_debug_log("net_sanity_error", role="join", kind="tick_frame", reason="negative_tick", tick_index=int(tick))
                return
            inputs_len = int(len(getattr(message, "frame_inputs", []) or []))
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
                    command_hash=str(getattr(message, "command_hash", "") or ""),
                    state_hash=str(getattr(message, "state_hash", "") or ""),
                )
            lockstep.ingest_tick_frame(message, now_ms=int(now_ms), local_command_hash="")
            queued_at = self._client_input_queued_at_ms.pop(int(tick), None)
            if queued_at is not None:
                latency_ms = max(0, int(now_ms) - int(queued_at))
                self._client_local_input_latency_ms = int(latency_ms)
                if self._client_local_input_latency_ewma_ms <= 0.0:
                    self._client_local_input_latency_ewma_ms = float(latency_ms)
                else:
                    self._client_local_input_latency_ewma_ms = float(
                        self._client_local_input_latency_ewma_ms * 0.9 + float(latency_ms) * 0.1
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
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_recv", role="join", kind=str(kind))

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
        if isinstance(message, KeepAlive):
            return
        if isinstance(message, DebugLogBatch):
            # Avoid recursive log forwarding (sending logs would itself get logged).
            return
        if isinstance(message, InputBatch):
            max_tick = -1
            min_tick = 2**31 - 1
            for sample in message.samples:
                tick = int(getattr(sample, "tick_index", 0) or 0)
                max_tick = max(int(max_tick), int(tick))
                min_tick = min(int(min_tick), int(tick))
            if max_tick >= 0 and (int(max_tick) < 5 or (int(max_tick) % 60) == 0):
                lan_debug_log(
                    "net_send",
                    role="join",
                    kind="input_batch",
                    reliable=bool(reliable),
                    slot_index=int(message.slot_index),
                    sample_count=int(len(message.samples)),
                    tick_min=int(min_tick) if min_tick != 2**31 - 1 else 0,
                    tick_max=int(max_tick),
                )
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_send", role="join", kind=str(kind), reliable=bool(reliable))

    def _trace_metrics(self, *, now_ms: int) -> None:
        if (int(now_ms) - int(self._metrics_last_log_ms)) < 1000:
            return
        self._metrics_last_log_ms = int(now_ms)

        tick_rate = max(1, int(self.cfg.tick_rate) or 1)
        delay_ticks = max(0, int(self.cfg.input_delay_ticks))
        delay_ms = int(round(float(delay_ticks) * 1000.0 / float(tick_rate)))

        role = str(self.cfg.role)
        if role == "host":
            lockstep = self.host_lockstep
            waiting_for = int(lockstep.waiting_for_inputs()) if lockstep is not None else 0
            stall_ms = 0
            if lockstep is not None and waiting_for > 0:
                stall_ms = max(0, int(now_ms) - int(lockstep.last_progress_ms))

            capture_tick = int(self.host_capture_tick)
            emit_tick = int(lockstep.next_emit_tick) if lockstep is not None else 0
            ready_frames = int(len(self.host_ready_frames))
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
        player_count = max(1, min(4, int(getattr(event, "player_count", 1) or 1)))
        self.host_lockstep = HostLockstepState(
            player_count=int(player_count),
            input_delay_ticks=int(self.cfg.input_delay_ticks),
        )
        self.host_capture_tick = 0
        self.host_ready_frames.clear()

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


__all__ = ["LanRuntime", "LanRuntimeConfig"]
