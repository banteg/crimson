from __future__ import annotations

import socket
import time
import uuid
from collections import OrderedDict, deque
from typing import Literal, cast

import msgspec

from ..game_modes import GameMode
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..replay.types import PackedPlayerInput
from .debug_log import lan_debug_log
from .lockstep_protocol import TickFrame
from .relay_protocol import (
    DEFAULT_PORT,
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PING_INTERVAL_MS,
    PROTOCOL_VERSION,
    RECONNECT_TIMEOUT_MS,
    ROLLBACK_MAX_TICKS,
    ClientHello,
    ClientWelcome,
    NetcodeMode,
    NetMessage,
    PeerDisconnect,
    Ping,
    Pong,
    RbInputBatch,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
    RbResyncRequest,
    RelayError,
    RoomJoin,
    RoomReady,
    RoomStart,
    RoomState,
    current_build_id,
)
from .relay_reliable import RelayReliableLink
from .relay_transport import PeerAddr, RelayUdpTransport
from .rollback import RollbackController
from .rollback_resync_v5 import (
    RbResyncAssemblerV5,
    RollbackResyncV5Error,
    build_rb_resync_messages,
    decode_mode_snapshot,
)
from .room_code import RoomCode
from .session_settings import room_create_from_session_settings, session_settings_for_relay


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


class _RollbackRuntimeConfigBase(msgspec.Struct):
    mode_id: GameMode
    player_count: int
    relay_host: str
    relay_port: int = DEFAULT_PORT
    room_code: RoomCode | None = None
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    netcode_mode: NetcodeMode = "rollback"
    tick_rate: int = 60
    input_delay_ticks: int = INPUT_DELAY_TICKS
    rollback_max_ticks: int = ROLLBACK_MAX_TICKS
    reconnect_timeout_ms: int = RECONNECT_TIMEOUT_MS
    sim_status: GameStatusData | None = None


class HostRollbackRuntimeConfig(_RollbackRuntimeConfigBase):
    role: Literal["host"] = "host"


class JoinRollbackRuntimeConfig(_RollbackRuntimeConfigBase):
    role: Literal["join"] = "join"


type RollbackRuntimeConfig = HostRollbackRuntimeConfig | JoinRollbackRuntimeConfig


ReconnectState = Literal["idle", "waiting_for_peer_reconnect", "self_reconnecting"]


class RollbackRuntime(msgspec.Struct):
    cfg: RollbackRuntimeConfig
    build_id: str = msgspec.field(default_factory=current_build_id)
    transport: RelayUdpTransport = cast(RelayUdpTransport, None)
    link: RelayReliableLink = msgspec.field(default_factory=RelayReliableLink)
    started: bool = False
    error: str = ""

    lobby_state_latest: RoomState | None = None
    match_start_event: RoomStart | None = None

    _server_addr: PeerAddr | None = None
    _peer_id: str = ""
    _accepted: bool = False
    _created_room: bool = False
    _sent_join_request: bool = False
    _joined_room: bool = False
    _sent_ready: bool = False
    _last_hello_ms: int = 0
    _last_seen_ms: int = 0
    _last_send_ms: int = 0
    _last_ping_ms: int = 0
    _reconnect_token: str = ""
    _paused_for_reconnect: bool = False
    _announced_room_code: RoomCode | None = None
    _reconnect_state: ReconnectState = "idle"

    _rollback: RollbackController | None = None
    _frame_queue: deque[TickFrame] = msgspec.field(default_factory=deque)
    _remote_seen_slots: set[int] = msgspec.field(default_factory=set)
    _pending_rollback_from: int | None = None

    _local_snapshot_blobs: OrderedDict[int, bytes] = msgspec.field(default_factory=OrderedDict)
    _pending_resync_snapshot: tuple[int, bytes] | None = None
    _pending_resync_snapshot_delivered: bool = False
    _resync_assembler: RbResyncAssemblerV5 | None = None
    _active_resync_request_id: str = ""
    _handled_resync_request_ids: set[str] = msgspec.field(default_factory=set)

    desync_count: int = 0
    last_desync_tick: int = -1
    last_desync_kind: str = ""
    last_desync_expected: str = ""
    last_desync_actual: str = ""

    rollback_count: int = 0
    prediction_mismatches: int = 0
    max_rollback_ticks_seen: int = 0
    resync_count: int = 0
    reconnect_count: int = 0
    _reconnect_deadline_ms: int = 0

    _neutral_input: PackedPlayerInput = msgspec.field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0, 0])

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
        self._sent_join_request = False
        self._joined_room = False
        self._sent_ready = False
        self._last_hello_ms = 0
        self._last_seen_ms = 0
        self._last_send_ms = 0
        self._last_ping_ms = 0
        self._reconnect_token = ""
        self._paused_for_reconnect = False
        self._reconnect_state = "idle"
        self._announced_room_code = None
        self._rollback = None
        self._frame_queue.clear()
        self._remote_seen_slots.clear()
        self._pending_rollback_from = None
        self._local_snapshot_blobs.clear()
        self._pending_resync_snapshot = None
        self._pending_resync_snapshot_delivered = False
        self._resync_assembler = None
        self._active_resync_request_id = ""
        self._handled_resync_request_ids.clear()
        self.started = False
        self.error = ""

    def lobby_state(self) -> RoomState | None:
        return self.lobby_state_latest

    def match_start(self) -> RoomStart | None:
        return self.match_start_event

    def debug_overlay_lines(self) -> list[str]:
        mode = str(self.cfg.netcode_mode)
        lines = [
            f"net({mode}): room={self.cfg.room_code or '?'!s} slot={int(self.local_slot_index)} started={int(self.started)}",
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

    def store_local_snapshot(self, tick_index: int, snapshot_blob: bytes) -> None:
        tick = max(0, int(tick_index))
        blob = bytes(snapshot_blob)
        self._local_snapshot_blobs[tick] = blob
        self._local_snapshot_blobs.move_to_end(tick, last=True)

        keep_from = int(tick) - 64
        for key in list(self._local_snapshot_blobs.keys()):
            if int(key) >= int(keep_from):
                continue
            self._local_snapshot_blobs.pop(int(key), None)

    def pop_rollback_from(self) -> int | None:
        value = self._pending_rollback_from
        self._pending_rollback_from = None
        return None if value is None else int(value)

    def pop_resync_snapshot(self) -> tuple[int, bytes] | None:
        snapshot = self._pending_resync_snapshot
        if snapshot is None:
            return None
        if bool(self._pending_resync_snapshot_delivered):
            return None
        self._pending_resync_snapshot_delivered = True
        return int(snapshot[0]), bytes(snapshot[1])

    def mark_resync_applied(self, tick_index: int) -> None:
        tick = max(0, int(tick_index))
        self._pending_resync_snapshot = None
        self._pending_resync_snapshot_delivered = False
        self._active_resync_request_id = ""
        controller = self._rollback
        if controller is not None:
            controller.reset_to_tick(int(tick) + 1)
        self._frame_queue.clear()
        self._paused_for_reconnect = False
        if self._reconnect_state != "self_reconnecting":
            self._reconnect_state = "idle"
        lan_debug_log(
            "resync_commit_applied",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            tick_index=int(tick),
        )

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

        if self._accepted and self._joined_room and (not self.started) and (not self._sent_ready):
            self._send(RoomReady(slot_index=max(0, int(self.local_slot_index)), ready=True), reliable=True, now_ms=int(now))
            self._sent_ready = True

        if self._accepted and (
            self._last_ping_ms <= 0 or (int(now) - int(self._last_ping_ms)) >= int(PING_INTERVAL_MS)
        ):
            self._send(Ping(stamp_ms=int(now)), reliable=False, now_ms=int(now))
            self._last_ping_ms = int(now)

        silent_ms = int(now) - int(self._last_seen_ms)
        if self._last_seen_ms > 0 and silent_ms >= int(LINK_TIMEOUT_MS):
            if self._can_self_reconnect():
                self._start_self_reconnect(now_ms=int(now), reason="timeout")
            elif not self._paused_for_reconnect:
                self.error = "timeout"

        if self._reconnect_deadline_ms > 0 and int(now) >= int(self._reconnect_deadline_ms):
            self.error = "reconnect_timeout"
            lan_debug_log(
                "reconnect_fail",
                role=str(self.cfg.role),
                room_code=str(self.cfg.room_code or ""),
                state=str(self._reconnect_state),
                reason="deadline",
            )

        self._drain_frames()

    def _send_hello_if_needed(self, *, now_ms: int) -> None:
        if self._accepted:
            if self._joined_room:
                return

            reconnecting = bool(self._reconnect_token) and str(self._reconnect_state) == "self_reconnecting"
            if reconnecting:
                if self._sent_join_request:
                    return
                self._sent_join_request = True
                self._send(
                    RoomJoin(room_code=self.cfg.room_code, reconnect_token=str(self._reconnect_token)),
                    reliable=True,
                    now_ms=int(now_ms),
                )
                return

            if str(self.cfg.role) == "host" and (not self._created_room):
                self._created_room = True
                settings = session_settings_for_relay(
                    mode_id=self.cfg.mode_id,
                    player_count=int(self.cfg.player_count),
                    quest_level=self.cfg.quest_level,
                    preserve_bugs=bool(self.cfg.preserve_bugs),
                    tick_rate=int(self.cfg.tick_rate),
                    input_delay_ticks=int(self.cfg.input_delay_ticks),
                    rollback_max_ticks=int(self.cfg.rollback_max_ticks),
                    netcode_mode=self.cfg.netcode_mode,
                )
                self._send(
                    room_create_from_session_settings(
                        settings,
                        status=self.cfg.sim_status,
                    ),
                    reliable=True,
                    now_ms=int(now_ms),
                )
                return
            if str(self.cfg.role) != "host":
                if self._sent_join_request:
                    return
                self._sent_join_request = True
                self._send(
                    RoomJoin(room_code=self.cfg.room_code, reconnect_token=""),
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

    def _handle_message(self, *, message: NetMessage, now_ms: int) -> None:
        lan_debug_log(
            "net_recv",
            role=str(self.cfg.role),
            kind=type(message).__name__,
            room_code=str(self.cfg.room_code or ""),
        )
        match message:
            case Pong():
                return

            case ClientWelcome():
                if not bool(message.accepted):
                    self.error = str(message.reason or "rejected")
                    return
                self._accepted = True
                self._peer_id = str(message.peer_id or "")
                if str(self._reconnect_state) == "self_reconnecting":
                    self._sent_join_request = False
                return

            case RelayError():
                self.error = str(message.reason or "relay_error")
                return

            case RoomState():
                self.lobby_state_latest = message
                self._joined_room = True
                if self._is_reconnect_in_progress() and self._room_state_has_local_slot(message):
                    self._finish_reconnect(now_ms=int(now_ms))
                if str(self.cfg.role) == "host":
                    self.cfg.room_code = message.room_code
                    self._announce_room_code(self.cfg.room_code)
                elif self.cfg.room_code != message.room_code:
                    self.cfg.room_code = message.room_code
                return

            case RoomStart():
                first_start = not bool(self.started)
                self.match_start_event = message
                self.started = True
                self._reconnect_deadline_ms = 0
                self._reconnect_token = str(message.reconnect_token or "")
                self._paused_for_reconnect = False
                self._reconnect_state = "idle"
                if first_start:
                    self._init_rollback(message)
                self._sent_ready = True
                if self.cfg.room_code != message.room_code:
                    self.cfg.room_code = message.room_code
                if str(self.cfg.role) == "host":
                    self._announce_room_code(self.cfg.room_code)
                return

            case PeerDisconnect():
                if not bool(self.started):
                    self.error = str(message.reason or "peer_disconnect")
                    return
                if self._reconnect_deadline_ms <= 0:
                    self.reconnect_count = int(self.reconnect_count) + 1
                self._reconnect_deadline_ms = int(now_ms) + int(self.cfg.reconnect_timeout_ms)
                self._paused_for_reconnect = True
                self._reconnect_state = "waiting_for_peer_reconnect"
                lan_debug_log(
                    "reconnect_start",
                    role=str(self.cfg.role),
                    room_code=str(self.cfg.room_code or ""),
                    state=str(self._reconnect_state),
                    reason=str(message.reason or "peer_disconnect"),
                )
                return

            case RbInputBatch():
                controller = self._rollback
                if controller is None:
                    return
                slot = int(message.slot_index)
                if int(slot) != int(controller.local_slot_index):
                    self._remote_seen_slots.add(int(slot))
                controller.ingest_remote_samples(slot_index=int(slot), samples=list(message.samples))
                self._sync_rollback_metrics(controller)

                rollback_from = controller.drain_rollback_from()
                if rollback_from is not None:
                    self._apply_rollback_from(controller=controller, from_tick=int(rollback_from), now_ms=int(now_ms))

                resync_from = controller.drain_resync_from()
                if resync_from is not None:
                    self._send_resync_request(
                        from_tick=int(resync_from),
                        reason="rollback_window_overflow",
                        now_ms=int(now_ms),
                    )
                return

            case RbResyncRequest():
                self._handle_resync_request(message=message, now_ms=int(now_ms))
                return

            case RbResyncBegin():
                self._handle_resync_begin(message=message)
                return

            case RbResyncChunk():
                self._handle_resync_chunk(message=message)
                return

            case RbResyncCommit():
                self._handle_resync_commit(message=message, now_ms=int(now_ms))
                return

            case _:
                return

    def _init_rollback(self, event: RoomStart) -> None:
        self._frame_queue.clear()
        self._remote_seen_slots.clear()
        self._pending_rollback_from = None
        self._local_snapshot_blobs.clear()
        self._pending_resync_snapshot = None
        self._pending_resync_snapshot_delivered = False
        self._resync_assembler = None
        self._active_resync_request_id = ""
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
                    commands=[],
                ),
            )

    def _sync_rollback_metrics(self, controller: RollbackController) -> None:
        self.rollback_count = int(controller.rollback_count)
        self.prediction_mismatches = int(controller.prediction_mismatches)
        self.max_rollback_ticks_seen = int(controller.max_rollback_distance)

    def _apply_rollback_from(self, *, controller: RollbackController, from_tick: int, now_ms: int) -> None:
        tick = max(0, int(from_tick))
        pending = self._pending_rollback_from
        if pending is None:
            self._pending_rollback_from = int(tick)
        else:
            self._pending_rollback_from = min(int(pending), int(tick))

        snapshot_tick = int(tick) - 1
        if self._latest_snapshot_at_or_before(snapshot_tick) is None:
            self._send_resync_request(from_tick=int(tick), reason="rollback_snapshot_missing", now_ms=int(now_ms))
            return

        rebuilt = controller.rebuild_emitted_from(int(tick))
        if rebuilt:
            rebuilt_queue = deque(frame for frame in self._frame_queue if int(frame.tick_index) < int(tick))
            for frame in rebuilt:
                rebuilt_queue.append(
                    TickFrame(
                        tick_index=int(frame.tick_index),
                        frame_inputs=[list(item) for item in frame.frame_inputs],
                        commands=[],
                    ),
                )
            self._frame_queue = rebuilt_queue

        lan_debug_log(
            "rollback_applied",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            from_tick=int(tick),
            rebuilt_frames=len(rebuilt),
        )

    def _send_resync_request(self, *, from_tick: int, reason: str, now_ms: int) -> None:
        request_id = uuid.uuid4().hex[:12]
        self.resync_count = int(self.resync_count) + 1
        self._paused_for_reconnect = True
        self._active_resync_request_id = str(request_id)
        self._send(
            RbResyncRequest(
                request_id=str(request_id),
                from_tick=max(0, int(from_tick)),
                reason=str(reason),
                requested_by_slot=max(0, int(self.local_slot_index)),
            ),
            reliable=True,
            now_ms=int(now_ms),
        )
        lan_debug_log(
            "resync_request_sent",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            request_id=str(request_id),
            from_tick=max(0, int(from_tick)),
            reason=str(reason),
        )

    def _handle_resync_request(self, *, message: RbResyncRequest, now_ms: int) -> None:
        if not self._is_host_slot():
            return

        request_id = str(message.request_id or "").strip()
        if not request_id:
            request_id = uuid.uuid4().hex[:12]
        if request_id in self._handled_resync_request_ids:
            return
        self._handled_resync_request_ids.add(str(request_id))

        snapshot = self._latest_snapshot_any()
        if snapshot is None:
            self._send(RelayError(reason="resync_snapshot_unavailable"), reliable=True, now_ms=int(now_ms))
            return
        snapshot_tick, payload = snapshot

        try:
            stream = build_rb_resync_messages(
                request_id=str(request_id),
                snapshot_tick=int(snapshot_tick),
                snapshot_blob=bytes(payload),
            )
        except RollbackResyncV5Error:
            self._send(RelayError(reason="resync_snapshot_invalid"), reliable=True, now_ms=int(now_ms))
            return

        self._send(stream.begin, reliable=True, now_ms=int(now_ms))
        for chunk in stream.chunks:
            self._send(chunk, reliable=True, now_ms=int(now_ms))
        self._send(stream.commit, reliable=True, now_ms=int(now_ms))

    def _handle_resync_begin(self, *, message: RbResyncBegin) -> None:
        request_id = str(message.request_id or "")
        if not request_id:
            return
        if self._active_resync_request_id and request_id != str(self._active_resync_request_id):
            return

        assembler = RbResyncAssemblerV5()
        try:
            assembler.begin(message)
        except RollbackResyncV5Error:
            return
        self._resync_assembler = assembler
        self._active_resync_request_id = str(request_id)
        self._paused_for_reconnect = True
        lan_debug_log(
            "resync_begin_recv",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            request_id=str(request_id),
            snapshot_tick=int(message.snapshot_tick),
            chunks=int(message.total_chunks),
        )

    def _handle_resync_chunk(self, *, message: RbResyncChunk) -> None:
        assembler = self._resync_assembler
        if assembler is None:
            return
        if str(message.request_id or "") != str(assembler.request_id):
            return
        try:
            assembler.push_chunk(message)
        except RollbackResyncV5Error:
            self._resync_assembler = None
            self.error = "resync_chunk_error"

    def _handle_resync_commit(self, *, message: RbResyncCommit, now_ms: int) -> None:
        assembler = self._resync_assembler
        if assembler is None:
            return
        if str(message.request_id or "") != str(assembler.request_id):
            return

        try:
            snapshot_tick, payload = assembler.finalize(message)
            decode_mode_snapshot(payload)
        except RollbackResyncV5Error:
            self._resync_assembler = None
            self.error = "resync_commit_error"
            return

        self._resync_assembler = None
        self._pending_resync_snapshot = (int(snapshot_tick), bytes(payload))
        self._pending_resync_snapshot_delivered = False
        self._paused_for_reconnect = True
        self._reconnect_deadline_ms = int(now_ms) + int(self.cfg.reconnect_timeout_ms)

    def _start_self_reconnect(self, *, now_ms: int, reason: str) -> None:
        if not self._can_self_reconnect():
            return
        if str(self._reconnect_state) == "self_reconnecting":
            return

        self.reconnect_count = int(self.reconnect_count) + 1
        self._paused_for_reconnect = True
        self._reconnect_state = "self_reconnecting"
        self._reconnect_deadline_ms = int(now_ms) + int(self.cfg.reconnect_timeout_ms)

        self._accepted = False
        self._joined_room = False
        self._created_room = False
        self._sent_join_request = False
        self._sent_ready = False
        self._peer_id = ""
        self._last_hello_ms = 0
        self._last_ping_ms = 0
        self.link = RelayReliableLink()

        lan_debug_log(
            "reconnect_start",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            state=str(self._reconnect_state),
            reason=str(reason),
        )

    def _finish_reconnect(self, *, now_ms: int) -> None:
        self._reconnect_deadline_ms = 0
        self._paused_for_reconnect = False
        previous = str(self._reconnect_state)
        self._reconnect_state = "idle"
        lan_debug_log(
            "reconnect_success",
            role=str(self.cfg.role),
            room_code=str(self.cfg.room_code or ""),
            previous_state=previous,
            now_ms=int(now_ms),
        )

    def _is_reconnect_in_progress(self) -> bool:
        return str(self._reconnect_state) in {"waiting_for_peer_reconnect", "self_reconnecting"}

    def _can_self_reconnect(self) -> bool:
        return bool(self.started) and bool(str(self._reconnect_token or "").strip())

    def _room_state_has_local_slot(self, room_state: RoomState) -> bool:
        slot_index = int(self.local_slot_index)
        if slot_index < 0 or slot_index >= len(room_state.slots):
            return False
        slot = room_state.slots[int(slot_index)]
        return bool(slot.connected)

    def _is_host_slot(self) -> bool:
        event = self.match_start_event
        if event is None:
            return str(self.cfg.role) == "host"
        return int(event.slot_index) == int(event.host_slot_index)

    def _latest_snapshot_any(self) -> tuple[int, bytes] | None:
        if not self._local_snapshot_blobs:
            return None
        tick = next(reversed(self._local_snapshot_blobs.keys()))
        payload = self._local_snapshot_blobs.get(int(tick))
        if payload is None:
            return None
        return int(tick), bytes(payload)

    def _latest_snapshot_at_or_before(self, tick_index: int) -> tuple[int, bytes] | None:
        target = int(tick_index)
        selected_tick: int | None = None
        for tick in self._local_snapshot_blobs:
            if int(tick) <= int(target):
                selected_tick = int(tick)
            else:
                break
        if selected_tick is None:
            return None
        payload = self._local_snapshot_blobs.get(int(selected_tick))
        if payload is None:
            return None
        return int(selected_tick), bytes(payload)

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

    def _announce_room_code(self, room_code: RoomCode | None) -> None:
        if room_code is None:
            return
        if room_code == self._announced_room_code:
            return
        self._announced_room_code = room_code
        print(f"[crimson] Invite code: {room_code}", flush=True)


__all__ = [
    "HostRollbackRuntimeConfig",
    "JoinRollbackRuntimeConfig",
    "RollbackRuntime",
    "RollbackRuntimeConfig",
]
