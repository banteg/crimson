from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import socket
import time

from ..replay.types import PackedPlayerInput
from .debug_log import lan_debug_log
from .relay_protocol import (
    DEFAULT_PORT,
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    RECONNECT_TIMEOUT_MS,
    ROLLBACK_MAX_TICKS,
    ClientHello,
    ClientWelcome,
    NetMessage,
    NetcodeMode,
    PeerDisconnect,
    Ping,
    Pong,
    RbInputBatch,
    RbResyncRequest,
    RelayError,
    RoomCreate,
    RoomJoin,
    RoomReady,
    RoomStart,
    RoomState,
    StatusSnapshot,
    current_build_id,
)
from .relay_reliable import RelayReliableLink
from .relay_transport import PeerAddr, RelayUdpTransport
from .rollback import RollbackController
from .legacy_protocol import PerkMenuClose, PerkMenuOpen, PerkPick, TickFrame


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


@dataclass(slots=True)
class NetRuntimeConfig:
    role: str
    mode_id: int
    player_count: int
    relay_host: str
    relay_port: int = DEFAULT_PORT
    room_code: str = ""
    quest_level: str = ""
    preserve_bugs: bool = False
    netcode_mode: NetcodeMode = "rollback"
    tick_rate: int = 60
    input_delay_ticks: int = INPUT_DELAY_TICKS
    rollback_max_ticks: int = ROLLBACK_MAX_TICKS
    reconnect_timeout_ms: int = RECONNECT_TIMEOUT_MS
    sim_status_snapshot: StatusSnapshot | None = None


@dataclass(slots=True)
class NetRuntime:
    cfg: NetRuntimeConfig
    build_id: str = field(default_factory=current_build_id)
    transport: RelayUdpTransport = field(init=False)
    link: RelayReliableLink = field(init=False, default_factory=RelayReliableLink)
    started: bool = field(init=False, default=False)
    error: str = field(init=False, default="")

    lobby_state_latest: RoomState | None = field(init=False, default=None)
    match_start_event: RoomStart | None = field(init=False, default=None)

    _server_addr: PeerAddr | None = field(init=False, default=None)
    _peer_id: str = field(init=False, default="")
    _accepted: bool = field(init=False, default=False)
    _created_room: bool = field(init=False, default=False)
    _joined_room: bool = field(init=False, default=False)
    _sent_ready: bool = field(init=False, default=False)
    _last_hello_ms: int = field(init=False, default=0)
    _last_seen_ms: int = field(init=False, default=0)
    _last_send_ms: int = field(init=False, default=0)
    _reconnect_token: str = field(init=False, default="")
    _paused_for_reconnect: bool = field(init=False, default=False)

    _rollback: RollbackController | None = field(init=False, default=None)
    _frame_queue: deque[TickFrame] = field(init=False, default_factory=deque)
    _remote_seen_slots: set[int] = field(init=False, default_factory=set)

    _client_perk_events: deque[PerkMenuOpen | PerkMenuClose | PerkPick] = field(init=False, default_factory=deque)

    desync_count: int = field(init=False, default=0)
    last_desync_tick: int = field(init=False, default=-1)
    last_desync_kind: str = field(init=False, default="")
    last_desync_expected: str = field(init=False, default="")
    last_desync_actual: str = field(init=False, default="")

    rollback_count: int = field(init=False, default=0)
    prediction_mismatches: int = field(init=False, default=0)
    max_rollback_ticks_seen: int = field(init=False, default=0)
    resync_count: int = field(init=False, default=0)
    reconnect_count: int = field(init=False, default=0)
    _reconnect_deadline_ms: int = field(init=False, default=0)

    _neutral_input: PackedPlayerInput = field(init=False, default_factory=lambda: [0.0, 0.0, [0.0, 0.0], 0])

    def __post_init__(self) -> None:
        self.transport = RelayUdpTransport(bind_host="0.0.0.0", bind_port=0)

    @property
    def local_slot_index(self) -> int:
        event = self.match_start_event
        if event is None:
            return 0 if str(self.cfg.role) == "host" else -1
        return int(event.slot_index)

    def open(self) -> None:
        if self._server_addr is not None:
            return
        host_raw = str(self.cfg.relay_host).strip()
        host = host_raw
        if host_raw:
            try:
                host = socket.gethostbyname(host_raw)
            except OSError:
                host = host_raw
        self._server_addr = (str(host), int(self.cfg.relay_port))
        self.transport.open()
        self._last_seen_ms = _now_ms()

    def close(self) -> None:
        self.transport.close()
        self._server_addr = None
        self._peer_id = ""
        self._accepted = False
        self._created_room = False
        self._joined_room = False
        self._sent_ready = False
        self._last_hello_ms = 0
        self._last_seen_ms = 0
        self._last_send_ms = 0
        self._reconnect_token = ""
        self._paused_for_reconnect = False
        self._rollback = None
        self._frame_queue.clear()
        self._remote_seen_slots.clear()
        self._client_perk_events.clear()
        self.started = False
        self.error = ""

    def lobby_state(self) -> RoomState | None:
        return self.lobby_state_latest

    def match_start(self) -> RoomStart | None:
        return self.match_start_event

    def debug_overlay_lines(self) -> list[str]:
        mode = str(self.cfg.netcode_mode)
        lines = [
            f"net({mode}): room={str(self.cfg.room_code or '?')} slot={int(self.local_slot_index)} started={int(self.started)}",
            (
                "rb: "
                f"rollbacks={int(self.rollback_count)} "
                f"mismatch={int(self.prediction_mismatches)} "
                f"max={int(self.max_rollback_ticks_seen)} "
                f"resync={int(self.resync_count)} "
                f"reconnect={int(self.reconnect_count)} "
                f"paused={int(self._paused_for_reconnect)}"
            ),
        ]
        if self.error:
            lines.append(f"net: error={self.error}")
        return lines

    def host_remote_inputs_ready(self) -> bool:
        if bool(self._paused_for_reconnect):
            return False
        if str(self.cfg.role) != "host":
            return True
        event = self.match_start_event
        if event is None:
            return False
        for slot in range(1, int(event.player_count)):
            if int(slot) not in self._remote_seen_slots:
                return False
        return True

    def pop_perk_event(self) -> PerkMenuOpen | PerkMenuClose | PerkPick | None:
        if not self._client_perk_events:
            return None
        return self._client_perk_events.popleft()

    def queue_local_input(self, packed_input: PackedPlayerInput, *, now_ms: int | None = None) -> None:
        if bool(self._paused_for_reconnect):
            return
        controller = self._rollback
        if controller is None:
            return
        batch = controller.queue_local_input(list(packed_input))
        self._sync_rollback_metrics(controller)
        self._send(batch, reliable=False, now_ms=(_now_ms() if now_ms is None else int(now_ms)))
        self._drain_frames()

    def pop_tick_frame(self) -> TickFrame | None:
        if bool(self._paused_for_reconnect):
            return None
        if not self._frame_queue:
            return None
        return self._frame_queue.popleft()

    def broadcast_tick_frame(self, frame: TickFrame, *, now_ms: int | None = None) -> None:
        # Rollback strategy uses input relay, not host-authored canonical tick frames.
        # Keep this method for compatibility with existing mode call-sites.
        _ = frame
        _ = now_ms

    def broadcast_perk_menu_open(self, *, tick_index: int, player_index: int = 0, now_ms: int | None = None) -> None:
        _ = tick_index
        _ = player_index
        _ = now_ms

    def broadcast_perk_menu_close(self, *, tick_index: int, player_index: int = 0, now_ms: int | None = None) -> None:
        _ = tick_index
        _ = player_index
        _ = now_ms

    def broadcast_perk_pick(
        self,
        *,
        tick_index: int,
        player_index: int = 0,
        choice_index: int,
        now_ms: int | None = None,
    ) -> None:
        _ = tick_index
        _ = player_index
        _ = choice_index
        _ = now_ms

    def note_desync(self, *, kind: str, tick_index: int, expected: str, actual: str) -> None:
        self.desync_count = int(self.desync_count) + 1
        self.last_desync_tick = int(tick_index)
        self.last_desync_kind = str(kind)
        self.last_desync_expected = str(expected)
        self.last_desync_actual = str(actual)

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        now = int(now_ms)
        if self._server_addr is None:
            return
        if self.error:
            return

        self._send_hello_if_needed(now_ms=int(now))

        for addr, packet in self.transport.recv_packets(max_packets=512):
            if addr != self._server_addr:
                continue
            self._last_seen_ms = int(now)
            messages, _dup = self.link.ingest_packet(packet, now_ms=int(now))
            for message in messages:
                self._handle_message(message=message, now_ms=int(now))

        for packet in self.link.poll_resends(now_ms=int(now)):
            try:
                self.transport.send_packet(self._server_addr, packet)
            except OSError:
                continue
            self._last_send_ms = int(now)

        if self._accepted and self._joined_room and (not self.started):
            if not self._sent_ready:
                self._send(RoomReady(slot_index=max(0, int(self.local_slot_index)), ready=True), reliable=True, now_ms=int(now))
                self._sent_ready = True

        if self.started:
            if self._last_send_ms <= 0 or (int(now) - int(self._last_send_ms)) >= 250:
                self._send(Ping(stamp_ms=int(now)), reliable=False, now_ms=int(now))

        if self._last_seen_ms > 0 and (int(now) - int(self._last_seen_ms)) >= int(LINK_TIMEOUT_MS):
            self.error = "timeout"

        if self._reconnect_deadline_ms > 0 and int(now) >= int(self._reconnect_deadline_ms):
            self.error = "reconnect_timeout"

        self._drain_frames()

    def _send_hello_if_needed(self, *, now_ms: int) -> None:
        if self._accepted:
            if self._joined_room:
                return
            if str(self.cfg.role) == "host" and (not self._created_room):
                self._created_room = True
                self._send(
                    RoomCreate(
                        mode_id=int(self.cfg.mode_id),
                        player_count=int(self.cfg.player_count),
                        quest_level=str(self.cfg.quest_level),
                        preserve_bugs=bool(self.cfg.preserve_bugs),
                        tick_rate=int(self.cfg.tick_rate),
                        input_delay_ticks=int(self.cfg.input_delay_ticks),
                        rollback_max_ticks=int(self.cfg.rollback_max_ticks),
                        netcode_mode=self.cfg.netcode_mode,
                        status_snapshot=self.cfg.sim_status_snapshot,
                    ),
                    reliable=True,
                    now_ms=int(now_ms),
                )
                return
            if str(self.cfg.role) != "host":
                if self._joined_room:
                    return
                self._joined_room = True
                self._send(
                    RoomJoin(room_code=str(self.cfg.room_code), reconnect_token=""),
                    reliable=True,
                    now_ms=int(now_ms),
                )
                return
            return

        if (int(now_ms) - int(self._last_hello_ms)) < 200:
            return
        self._last_hello_ms = int(now_ms)
        self._send(
            ClientHello(
                protocol_version=int(PROTOCOL_VERSION),
                build_id=str(self.build_id),
                peer_name="",
            ),
            reliable=True,
            now_ms=int(now_ms),
        )

    def _handle_message(self, *, message: object, now_ms: int) -> None:
        if isinstance(message, Pong):
            return

        if isinstance(message, ClientWelcome):
            if not bool(message.accepted):
                self.error = str(message.reason or "rejected")
                return
            self._accepted = True
            self._peer_id = str(message.peer_id or "")
            return

        if isinstance(message, RelayError):
            self.error = str(message.reason or "relay_error")
            return

        if isinstance(message, RoomState):
            self.lobby_state_latest = message
            if self._reconnect_deadline_ms > 0:
                connected = sum(1 for slot in message.slots if bool(slot.connected))
                if int(connected) >= max(1, int(message.player_count)):
                    self._reconnect_deadline_ms = 0
                    self._paused_for_reconnect = False
            if str(self.cfg.role) == "host":
                self.cfg.room_code = str(message.room_code or "")
                self._joined_room = True
            return

        if isinstance(message, RoomStart):
            self.match_start_event = message
            self.started = True
            self._reconnect_deadline_ms = 0
            self._reconnect_token = str(message.reconnect_token or "")
            self._paused_for_reconnect = False
            self._init_rollback(message)
            self._sent_ready = True
            if str(self.cfg.room_code or "") != str(message.room_code or ""):
                self.cfg.room_code = str(message.room_code or "")
            return

        if isinstance(message, PeerDisconnect):
            if self._reconnect_deadline_ms <= 0:
                self.reconnect_count = int(self.reconnect_count) + 1
            self._reconnect_deadline_ms = int(now_ms) + int(self.cfg.reconnect_timeout_ms)
            self._paused_for_reconnect = True
            return

        if isinstance(message, RbInputBatch):
            controller = self._rollback
            if controller is None:
                return
            slot = int(message.slot_index)
            if int(slot) != int(controller.local_slot_index):
                self._remote_seen_slots.add(int(slot))
            controller.ingest_remote_samples(slot_index=int(slot), samples=list(message.samples))
            self._sync_rollback_metrics(controller)
            resync_from = controller.drain_resync_from()
            if resync_from is not None:
                self.resync_count = int(self.resync_count) + 1
                self._paused_for_reconnect = True
                self._send(
                    RbResyncRequest(from_tick=int(resync_from), reason="rollback_window_overflow"),
                    reliable=True,
                    now_ms=int(now_ms),
                )
            return

    def _init_rollback(self, event: RoomStart) -> None:
        self._frame_queue.clear()
        self._remote_seen_slots.clear()
        self._rollback = RollbackController(
            player_count=max(1, int(event.player_count)),
            local_slot_index=max(0, int(event.slot_index)),
            input_delay_ticks=max(0, int(event.input_delay_ticks)),
            max_rollback_ticks=max(1, int(event.rollback_max_ticks)),
        )

        # Prime initial delay ticks with neutral inputs.
        delay = max(0, int(event.input_delay_ticks))
        player_count = max(1, int(event.player_count))
        for tick in range(delay):
            for slot in range(player_count):
                self._rollback._known_by_slot[int(slot)][int(tick)] = list(self._neutral_input)

    def _drain_frames(self) -> None:
        if bool(self._paused_for_reconnect):
            return
        controller = self._rollback
        if controller is None:
            return
        while True:
            frame = controller.pop_frame()
            if frame is None:
                break
            self._frame_queue.append(
                TickFrame(
                    tick_index=int(frame.tick_index),
                    frame_inputs=[list(item) for item in frame.frame_inputs],
                    command_hash="",
                    state_hash="",
                )
            )

    def _sync_rollback_metrics(self, controller: RollbackController) -> None:
        self.rollback_count = int(controller.rollback_count)
        self.prediction_mismatches = int(controller.prediction_mismatches)
        self.max_rollback_ticks_seen = int(controller.max_rollback_distance)

    def _send(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        addr = self._server_addr
        if addr is None:
            return
        packet = self.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(addr, packet)
        except OSError:
            return
        self._last_send_ms = int(now_ms)
        if not isinstance(message, Ping):
            lan_debug_log(
                "net_send",
                role=str(self.cfg.role),
                kind=type(message).__name__,
                reliable=bool(reliable),
                room_code=str(self.cfg.room_code or ""),
            )


__all__ = ["NetRuntime", "NetRuntimeConfig"]
