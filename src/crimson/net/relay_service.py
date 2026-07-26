from __future__ import annotations

import random
import string
import time
import uuid

import msgspec
import structlog

from ..game_modes import GameMode
from ..logging import ensure_structlog_stdlib_defaults
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from .relay_protocol import (
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    RECONNECT_TIMEOUT_MS,
    ClientHello,
    ClientWelcome,
    LockstepControl,
    LockstepInputBatch,
    LockstepTickFrame,
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
    RelaySlot,
    RoomCreate,
    RoomJoin,
    RoomReady,
    builds_compatible,
)
from .relay_reliable import RelayReliableLink
from .relay_transport import PeerAddr, RelayUdpTransport
from .room_code import ROOM_CODE_LENGTH, RoomCode
from .session_settings import (
    room_start_from_session_settings,
    room_state_from_session_settings,
    session_settings_for_relay,
    session_settings_from_room_create,
)


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


def _room_code(rand: random.Random) -> RoomCode:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rand.choice(alphabet) for _ in range(int(ROOM_CODE_LENGTH)))


class RelayServerConfig(msgspec.Struct):
    bind_host: str = "0.0.0.0"
    bind_port: int = 31993
    link_timeout_ms: int = LINK_TIMEOUT_MS
    reconnect_timeout_ms: int = RECONNECT_TIMEOUT_MS
    max_rooms: int = 2048


class _Peer(msgspec.Struct):
    addr: PeerAddr
    link: RelayReliableLink = msgspec.field(default_factory=RelayReliableLink)
    peer_id: str = ""
    build_id: str = ""
    peer_name: str = ""
    room_code: RoomCode | None = None
    slot_index: int = -1
    last_seen_ms: int = 0


class _RoomSlot(msgspec.Struct):
    slot_index: int
    peer_id: str = ""
    peer_name: str = ""
    ready: bool = False
    reconnect_token: str = ""
    disconnected_ms: int = 0

    @property
    def connected(self) -> bool:
        return bool(self.peer_id)


class _Room(msgspec.Struct):
    room_code: RoomCode
    session_id: str
    mode_id: GameMode
    player_count: int
    quest_level: QuestLevel | None
    preserve_bugs: bool
    tick_rate: int
    input_delay_ticks: int
    rollback_max_ticks: int
    netcode_mode: NetcodeMode
    status: GameStatusData | None = None
    started: bool = False
    seed: int = 0
    start_tick: int = 0
    slots: list[_RoomSlot] = msgspec.field(default_factory=list)

    def all_ready(self) -> bool:
        for slot in self.slots:
            if not slot.connected:
                return False
            if not bool(slot.ready):
                return False
        return True


_FORWARD_RELIABLE_TYPES = (
    RbResyncRequest,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
    LockstepTickFrame,
    LockstepControl,
)


class RelayServer:
    """In-memory UDP relay + invite-code lobby service."""

    def __init__(self, cfg: RelayServerConfig) -> None:
        ensure_structlog_stdlib_defaults()
        self.cfg = cfg
        self.transport = RelayUdpTransport(bind_host=str(cfg.bind_host), bind_port=int(cfg.bind_port))
        self._rooms: dict[RoomCode, _Room] = {}
        self._peers_by_addr: dict[PeerAddr, _Peer] = {}
        self._peers_by_id: dict[str, _Peer] = {}
        self._room_by_reconnect: dict[str, tuple[RoomCode, int]] = {}
        self._rand = random.Random()
        self.log = structlog.stdlib.get_logger("crimson.relay").bind(
            component="relay_service",
            bind_host=str(cfg.bind_host),
            bind_port=int(cfg.bind_port),
        )

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    def open(self) -> None:
        self.transport.open()
        self.log.info(
            "relay_open",
            bound_port=int(self.bound_port),
            link_timeout_ms=int(self.cfg.link_timeout_ms),
            reconnect_timeout_ms=int(self.cfg.reconnect_timeout_ms),
            max_rooms=int(self.cfg.max_rooms),
        )

    def close(self) -> None:
        self.transport.close()
        room_count = len(self._rooms)
        peer_count = len(self._peers_by_id)
        self._rooms.clear()
        self._peers_by_addr.clear()
        self._peers_by_id.clear()
        self._room_by_reconnect.clear()
        self.log.info("relay_close", room_count=int(room_count), peer_count=int(peer_count))

    def serve_forever(self, *, tick_ms: int = 8) -> None:
        self.open()
        try:
            while True:
                now = _now_ms()
                self.update(now_ms=int(now))
                time.sleep(max(0.0, float(tick_ms) * 0.001))
        finally:
            self.close()

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        now = int(now_ms)

        for addr, packet in self.transport.recv_packets(max_packets=512):
            peer = self._peers_by_addr.get(addr)
            if peer is None:
                if not isinstance(packet.message, ClientHello):
                    self.log.debug(
                        "relay_drop_unregistered_packet",
                        addr=self._addr_text(addr),
                        kind=type(packet.message).__name__,
                        reliable=bool(packet.reliable),
                        seq=int(packet.seq),
                    )
                    continue
                self._handle_client_hello(addr=addr, message=packet.message, now_ms=int(now))
                peer = self._peers_by_addr.get(addr)
                if peer is not None and bool(packet.reliable) and int(packet.seq) > 0:
                    peer.link.prime_recv_seq(int(packet.seq))
                    self.log.debug(
                        "relay_prime_recv_seq",
                        peer_id=str(peer.peer_id),
                        seq=int(packet.seq),
                    )
                continue

            peer.last_seen_ms = int(now)
            messages, duplicate = peer.link.ingest_packet(packet, now_ms=int(now))
            if bool(duplicate):
                self.log.debug(
                    "relay_recv_duplicate",
                    peer_id=str(peer.peer_id),
                    addr=self._addr_text(addr),
                    seq=int(packet.seq),
                    ack=int(packet.ack),
                )
            for message in messages:
                self._handle_message(peer=peer, message=message, now_ms=int(now))

        self._poll_resends(now_ms=int(now))
        self._prune_timeouts(now_ms=int(now))

    def _handle_client_hello(self, *, addr: PeerAddr, message: ClientHello, now_ms: int) -> None:
        if int(message.protocol_version) != int(PROTOCOL_VERSION):
            self.log.warning(
                "relay_protocol_mismatch",
                addr=self._addr_text(addr),
                peer_protocol=int(message.protocol_version),
                expected_protocol=int(PROTOCOL_VERSION),
                build_id=str(message.build_id or ""),
            )
            temp = RelayReliableLink()
            packet = temp.build_packet(
                ClientWelcome(
                    accepted=False,
                    reason="protocol_mismatch_v5_required",
                    protocol_version=int(PROTOCOL_VERSION),
                ),
                reliable=True,
                now_ms=int(now_ms),
            )
            self.transport.send_packet(addr, packet)
            return

        peer_id = uuid.uuid4().hex[:12]
        peer = _Peer(
            addr=addr,
            peer_id=str(peer_id),
            build_id=str(message.build_id or ""),
            peer_name=str(message.peer_name or ""),
            last_seen_ms=int(now_ms),
        )
        self._peers_by_addr[addr] = peer
        self._peers_by_id[str(peer_id)] = peer
        self.log.info(
            "relay_peer_connected",
            peer_id=str(peer_id),
            addr=self._addr_text(addr),
            build_id=str(message.build_id or ""),
            peer_name=str(message.peer_name or ""),
            peer_count=len(self._peers_by_id),
        )

        self._send_peer(
            peer,
            ClientWelcome(
                accepted=True,
                reason="",
                protocol_version=int(PROTOCOL_VERSION),
                build_id=str(message.build_id or ""),
                peer_id=str(peer_id),
            ),
            reliable=True,
            now_ms=int(now_ms),
        )

    def _handle_message(self, *, peer: _Peer, message: NetMessage, now_ms: int) -> None:
        request_id = ""
        match message:
            case RbResyncRequest() | RbResyncBegin() | RbResyncChunk() | RbResyncCommit():
                request_id = str(message.request_id)
            case _:
                request_id = ""
        self.log.debug(
            "relay_message_received",
            peer_id=str(peer.peer_id),
            room_code=str(peer.room_code or ""),
            slot_index=int(peer.slot_index),
            kind=type(message).__name__,
            request_id=request_id,
            now_ms=int(now_ms),
        )
        match message:
            case Ping():
                self._send_peer(peer, Pong(stamp_ms=int(message.stamp_ms)), reliable=False, now_ms=int(now_ms))
                return

            case RoomCreate():
                self._handle_room_create(peer=peer, message=message, now_ms=int(now_ms))
                return

            case RoomJoin():
                self._handle_room_join(peer=peer, message=message, now_ms=int(now_ms))
                return

            case RoomReady():
                self._handle_room_ready(peer=peer, message=message, now_ms=int(now_ms))
                return

            case RbInputBatch() | RbResyncRequest() | RbResyncBegin() | RbResyncChunk() | RbResyncCommit():
                self._forward_room_message(peer=peer, message=message, now_ms=int(now_ms))
                return

            case LockstepInputBatch() | LockstepTickFrame() | LockstepControl():
                self._forward_room_message(peer=peer, message=message, now_ms=int(now_ms))
                return

            case _:
                self.log.warning(
                    "relay_message_unhandled",
                    peer_id=str(peer.peer_id),
                    kind=type(message).__name__,
                    room_code=str(peer.room_code or ""),
                )

    def _handle_room_create(self, *, peer: _Peer, message: RoomCreate, now_ms: int) -> None:
        if peer.room_code:
            self.log.warning(
                "relay_room_create_rejected",
                reason="already_in_room",
                peer_id=str(peer.peer_id),
                room_code=str(peer.room_code or ""),
            )
            self._send_peer(peer, RelayError(reason="already_in_room"), reliable=True, now_ms=int(now_ms))
            return
        if len(self._rooms) >= int(self.cfg.max_rooms):
            self.log.warning(
                "relay_room_create_rejected",
                reason="room_capacity",
                peer_id=str(peer.peer_id),
                room_count=len(self._rooms),
                max_rooms=int(self.cfg.max_rooms),
            )
            self._send_peer(peer, RelayError(reason="room_capacity"), reliable=True, now_ms=int(now_ms))
            return

        code: RoomCode | None = None
        for _ in range(32):
            candidate = _room_code(self._rand)
            if candidate in self._rooms:
                continue
            code = candidate
            break
        if code is None:
            self.log.error(
                "relay_room_create_rejected",
                reason="room_code_exhausted",
                peer_id=str(peer.peer_id),
            )
            self._send_peer(peer, RelayError(reason="room_code_exhausted"), reliable=True, now_ms=int(now_ms))
            return

        settings = session_settings_from_room_create(message)
        player_count = int(settings.player_count)
        slots = [_RoomSlot(slot_index=i) for i in range(int(player_count))]
        host_slot = slots[0]
        host_slot.peer_id = str(peer.peer_id)
        host_slot.peer_name = str(peer.peer_name)
        host_slot.ready = True
        host_slot.reconnect_token = uuid.uuid4().hex

        room = _Room(
            room_code=code,
            session_id=uuid.uuid4().hex[:12],
            mode_id=settings.mode_id,
            player_count=int(player_count),
            quest_level=settings.quest_level,
            preserve_bugs=bool(settings.preserve_bugs),
            tick_rate=int(settings.tick_rate),
            input_delay_ticks=int(settings.input_delay_ticks),
            rollback_max_ticks=int(settings.rollback_max_ticks),
            netcode_mode=settings.netcode_mode,
            status=message.status,
            slots=slots,
        )
        self._rooms[code] = room
        self._room_by_reconnect[str(host_slot.reconnect_token)] = (code, 0)

        peer.room_code = code
        peer.slot_index = 0
        self.log.info(
            "relay_room_created",
            room_code=str(room.room_code),
            session_id=str(room.session_id),
            host_peer_id=str(peer.peer_id),
            mode_id=int(room.mode_id),
            player_count=int(room.player_count),
            netcode_mode=str(room.netcode_mode),
        )

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

    def _handle_room_join(self, *, peer: _Peer, message: RoomJoin, now_ms: int) -> None:
        room_code = message.room_code
        reconnect_token = str(message.reconnect_token or "").strip()

        if peer.room_code:
            self.log.warning(
                "relay_room_join_rejected",
                reason="already_in_room",
                peer_id=str(peer.peer_id),
                room_code=str(peer.room_code or ""),
            )
            self._send_peer(peer, RelayError(reason="already_in_room"), reliable=True, now_ms=int(now_ms))
            return

        room: _Room | None = None
        slot_index = -1

        if reconnect_token:
            mapping = self._room_by_reconnect.get(str(reconnect_token))
            if mapping is not None:
                room = self._rooms.get(mapping[0])
                slot_index = int(mapping[1])

        if room is None:
            room = self._rooms.get(room_code) if room_code is not None else None
            if room is None:
                self.log.warning(
                    "relay_room_join_rejected",
                    reason="room_not_found",
                    peer_id=str(peer.peer_id),
                    room_code=str(room_code),
                )
                self._send_peer(peer, RelayError(reason="room_not_found"), reliable=True, now_ms=int(now_ms))
                return
            slot_index = self._next_free_slot(room)
            if slot_index < 0:
                self.log.warning(
                    "relay_room_join_rejected",
                    reason="room_full",
                    peer_id=str(peer.peer_id),
                    room_code=str(room.room_code),
                )
                self._send_peer(peer, RelayError(reason="room_full"), reliable=True, now_ms=int(now_ms))
                return

        slot = room.slots[int(slot_index)]
        if slot.peer_id and slot.peer_id != str(peer.peer_id):
            age = max(0, int(now_ms) - int(slot.disconnected_ms or 0))
            if age < int(self.cfg.reconnect_timeout_ms):
                self.log.warning(
                    "relay_room_join_rejected",
                    reason="slot_busy",
                    peer_id=str(peer.peer_id),
                    room_code=str(room.room_code),
                    slot_index=int(slot_index),
                    age_ms=int(age),
                )
                self._send_peer(peer, RelayError(reason="slot_busy"), reliable=True, now_ms=int(now_ms))
                return

        host_slot = room.slots[0]
        host_peer = self._peers_by_id.get(str(host_slot.peer_id))
        if (
            host_peer is not None
            and host_peer.build_id
            and peer.build_id
            and not builds_compatible(str(peer.build_id), str(host_peer.build_id))
        ):
            self.log.warning(
                "relay_room_join_rejected",
                reason="build_mismatch",
                peer_id=str(peer.peer_id),
                room_code=str(room.room_code),
                peer_build=str(peer.build_id),
                host_build=str(host_peer.build_id),
            )
            self._send_peer(peer, RelayError(reason="build_mismatch"), reliable=True, now_ms=int(now_ms))
            return

        slot.peer_id = str(peer.peer_id)
        slot.peer_name = str(peer.peer_name)
        slot.ready = bool(room.started)
        slot.disconnected_ms = 0
        if not slot.reconnect_token:
            slot.reconnect_token = uuid.uuid4().hex
        self._room_by_reconnect[str(slot.reconnect_token)] = (room.room_code, int(slot.slot_index))

        peer.room_code = room.room_code
        peer.slot_index = int(slot.slot_index)
        self.log.info(
            "relay_room_joined",
            room_code=str(room.room_code),
            peer_id=str(peer.peer_id),
            slot_index=int(slot.slot_index),
            reconnect=bool(reconnect_token),
            room_started=bool(room.started),
        )

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

        if room.started:
            self._send_room_start(peer=peer, room=room, now_ms=int(now_ms))

    def _handle_room_ready(self, *, peer: _Peer, message: RoomReady, now_ms: int) -> None:
        room = self._rooms.get(peer.room_code) if peer.room_code is not None else None
        if room is None:
            self.log.warning(
                "relay_room_ready_rejected",
                reason="not_in_room",
                peer_id=str(peer.peer_id),
            )
            self._send_peer(peer, RelayError(reason="not_in_room"), reliable=True, now_ms=int(now_ms))
            return
        slot_index = int(peer.slot_index)
        if slot_index < 0 or slot_index >= len(room.slots):
            self.log.warning(
                "relay_room_ready_rejected",
                reason="bad_slot",
                peer_id=str(peer.peer_id),
                slot_index=int(slot_index),
                room_code=str(room.room_code),
            )
            self._send_peer(peer, RelayError(reason="bad_slot"), reliable=True, now_ms=int(now_ms))
            return
        slot = room.slots[int(slot_index)]
        if slot.peer_id != str(peer.peer_id):
            self.log.warning(
                "relay_room_ready_rejected",
                reason="slot_owner_mismatch",
                peer_id=str(peer.peer_id),
                slot_index=int(slot_index),
                room_code=str(room.room_code),
            )
            self._send_peer(peer, RelayError(reason="slot_owner_mismatch"), reliable=True, now_ms=int(now_ms))
            return
        slot.ready = bool(message.ready)
        self.log.debug(
            "relay_room_ready_updated",
            room_code=str(room.room_code),
            peer_id=str(peer.peer_id),
            slot_index=int(slot_index),
            ready=bool(slot.ready),
        )

        if (not room.started) and room.all_ready():
            room.started = True
            room.seed = int((now_ms * 1103515245 + 12345) & 0xFFFFFFFF)
            room.start_tick = 0
            self.log.info(
                "relay_room_started",
                room_code=str(room.room_code),
                session_id=str(room.session_id),
                seed=int(room.seed),
                player_count=int(room.player_count),
            )
            self._broadcast_room_start(room=room, now_ms=int(now_ms))

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

    def _forward_room_message(self, *, peer: _Peer, message: NetMessage, now_ms: int) -> None:
        room = self._rooms.get(peer.room_code) if peer.room_code is not None else None
        if room is None:
            self.log.warning(
                "relay_forward_rejected",
                reason="not_in_room",
                peer_id=str(peer.peer_id),
                kind=type(message).__name__,
            )
            self._send_peer(peer, RelayError(reason="not_in_room"), reliable=True, now_ms=int(now_ms))
            return

        sender_slot = int(peer.slot_index)
        host_slot = 0
        if int(sender_slot) < 0 or int(sender_slot) >= len(room.slots):
            self.log.warning(
                "relay_forward_rejected",
                reason="bad_sender_slot",
                room_code=str(room.room_code),
                from_peer_id=str(peer.peer_id),
                kind=type(message).__name__,
                sender_slot=int(sender_slot),
            )
            self._send_peer(peer, RelayError(reason="bad_sender_slot"), reliable=True, now_ms=int(now_ms))
            return

        request_id = ""
        if isinstance(message, RbResyncRequest):
            request_id = str(message.request_id or "")
            if int(sender_slot) == int(host_slot):
                self.log.warning(
                    "relay_forward_rejected",
                    reason="invalid_resync_sender",
                    room_code=str(room.room_code),
                    from_peer_id=str(peer.peer_id),
                    kind=type(message).__name__,
                    sender_slot=int(sender_slot),
                    request_id=str(request_id),
                )
                self._send_peer(peer, RelayError(reason="invalid_resync_sender"), reliable=True, now_ms=int(now_ms))
                return
        elif isinstance(message, (RbResyncBegin, RbResyncChunk, RbResyncCommit)):
            request_id = str(message.request_id)
            if int(sender_slot) != int(host_slot):
                self.log.warning(
                    "relay_forward_rejected",
                    reason="invalid_resync_sender",
                    room_code=str(room.room_code),
                    from_peer_id=str(peer.peer_id),
                    kind=type(message).__name__,
                    sender_slot=int(sender_slot),
                    request_id=str(request_id),
                )
                self._send_peer(peer, RelayError(reason="invalid_resync_sender"), reliable=True, now_ms=int(now_ms))
                return

        reliable = isinstance(message, _FORWARD_RELIABLE_TYPES)
        if isinstance(message, LockstepInputBatch):
            reliable = False
        forwarded = 0
        for slot in room.slots:
            if (not slot.connected) or slot.peer_id == str(peer.peer_id):
                continue
            dst = self._peers_by_id.get(str(slot.peer_id))
            if dst is None:
                continue
            self._send_peer(dst, message, reliable=bool(reliable), now_ms=int(now_ms))
            forwarded += 1
        self.log.debug(
            "relay_forwarded",
            room_code=str(room.room_code),
            from_peer_id=str(peer.peer_id),
            kind=type(message).__name__,
            reliable=bool(reliable),
            recipient_count=int(forwarded),
            request_id=str(request_id),
        )

    def _broadcast_room_state(self, *, room: _Room, now_ms: int) -> None:
        slots = [
            RelaySlot(
                slot_index=int(slot.slot_index),
                connected=bool(slot.connected),
                ready=bool(slot.ready),
                is_host=int(slot.slot_index) == 0,
                peer_name=str(slot.peer_name or ""),
            )
            for slot in room.slots
        ]
        settings = session_settings_for_relay(
            mode_id=room.mode_id,
            player_count=int(room.player_count),
            quest_level=room.quest_level,
            preserve_bugs=bool(room.preserve_bugs),
            tick_rate=int(room.tick_rate),
            input_delay_ticks=int(room.input_delay_ticks),
            rollback_max_ticks=int(room.rollback_max_ticks),
            netcode_mode=room.netcode_mode,
        )
        state = room_state_from_session_settings(
            settings,
            room_code=str(room.room_code),
            session_id=str(room.session_id),
            slots=slots,
            all_ready=bool(room.all_ready()),
            started=bool(room.started),
        )
        connected = 0
        for slot in room.slots:
            if not slot.connected:
                continue
            peer = self._peers_by_id.get(str(slot.peer_id))
            if peer is None:
                continue
            connected += 1
            self._send_peer(peer, state, reliable=True, now_ms=int(now_ms))
        self.log.debug(
            "relay_room_state_broadcast",
            room_code=str(room.room_code),
            started=bool(room.started),
            all_ready=bool(room.all_ready()),
            connected_players=int(connected),
            expected_players=int(room.player_count),
        )

    def _broadcast_room_start(self, *, room: _Room, now_ms: int) -> None:
        for slot in room.slots:
            if not slot.connected:
                continue
            peer = self._peers_by_id.get(str(slot.peer_id))
            if peer is None:
                continue
            self._send_room_start(peer=peer, room=room, now_ms=int(now_ms))

    def _send_room_start(self, *, peer: _Peer, room: _Room, now_ms: int) -> None:
        slot_index = int(peer.slot_index)
        reconnect_token = ""
        if 0 <= int(slot_index) < len(room.slots):
            reconnect_token = str(room.slots[int(slot_index)].reconnect_token)
        settings = session_settings_for_relay(
            mode_id=room.mode_id,
            player_count=int(room.player_count),
            quest_level=room.quest_level,
            preserve_bugs=bool(room.preserve_bugs),
            tick_rate=int(room.tick_rate),
            input_delay_ticks=int(room.input_delay_ticks),
            rollback_max_ticks=int(room.rollback_max_ticks),
            netcode_mode=room.netcode_mode,
        )
        self._send_peer(
            peer,
            room_start_from_session_settings(
                settings,
                room_code=str(room.room_code),
                session_id=str(room.session_id),
                seed=int(room.seed),
                start_tick=int(room.start_tick),
                slot_index=int(slot_index),
                host_slot_index=0,
                reconnect_token=str(reconnect_token),
                status=room.status,
            ),
            reliable=True,
            now_ms=int(now_ms),
        )
        self.log.info(
            "relay_room_start_sent",
            room_code=str(room.room_code),
            session_id=str(room.session_id),
            peer_id=str(peer.peer_id),
            slot_index=int(slot_index),
        )

    def _send_peer(self, peer: _Peer, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        packet = peer.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        self.transport.send_packet(peer.addr, packet)
        self.log.debug(
            "relay_send",
            peer_id=str(peer.peer_id),
            addr=self._addr_text(peer.addr),
            room_code=str(peer.room_code or ""),
            slot_index=int(peer.slot_index),
            kind=type(message).__name__,
            reliable=bool(reliable),
            seq=int(packet.seq),
            ack=int(packet.ack),
        )

    def _poll_resends(self, *, now_ms: int) -> None:
        for peer in self._peers_by_id.values():
            for packet in peer.link.poll_resends(now_ms=int(now_ms)):
                self.transport.send_packet(peer.addr, packet)
                self.log.debug(
                    "relay_resend",
                    peer_id=str(peer.peer_id),
                    addr=self._addr_text(peer.addr),
                    kind=type(packet.message).__name__,
                    seq=int(packet.seq),
                    ack=int(packet.ack),
                )

    def _prune_timeouts(self, *, now_ms: int) -> None:
        timeout = max(250, int(self.cfg.link_timeout_ms))
        for peer_id, peer in list(self._peers_by_id.items()):
            if (int(now_ms) - int(peer.last_seen_ms)) < int(timeout):
                continue
            self.log.info(
                "relay_peer_timeout",
                peer_id=str(peer.peer_id),
                room_code=str(peer.room_code or ""),
                slot_index=int(peer.slot_index),
                timeout_ms=int(timeout),
                silent_ms=int(now_ms) - int(peer.last_seen_ms),
            )
            self._disconnect_peer(peer=peer, reason="timeout", now_ms=int(now_ms))
            self._peers_by_id.pop(str(peer_id), None)
            self._peers_by_addr.pop(peer.addr, None)

    def _disconnect_peer(self, *, peer: _Peer, reason: str, now_ms: int) -> None:
        room = self._rooms.get(peer.room_code) if peer.room_code is not None else None
        if room is None:
            self.log.info(
                "relay_peer_disconnected_without_room",
                peer_id=str(peer.peer_id),
                reason=str(reason),
            )
            return
        if 0 <= int(peer.slot_index) < len(room.slots):
            slot = room.slots[int(peer.slot_index)]
            if slot.peer_id == str(peer.peer_id):
                slot.peer_id = ""
                slot.ready = False
                slot.disconnected_ms = int(now_ms)
                slot.peer_name = ""

        self.log.info(
            "relay_peer_disconnected",
            peer_id=str(peer.peer_id),
            room_code=str(room.room_code),
            slot_index=int(peer.slot_index),
            reason=str(reason),
        )
        self._broadcast_room_state(room=room, now_ms=int(now_ms))

        notice = PeerDisconnect(slot_index=int(peer.slot_index), reason=str(reason))
        for slot in room.slots:
            if not slot.connected:
                continue
            dst = self._peers_by_id.get(str(slot.peer_id))
            if dst is None:
                continue
            self._send_peer(dst, notice, reliable=True, now_ms=int(now_ms))

        if all((not slot.connected) for slot in room.slots):
            self._rooms.pop(room.room_code, None)
            self.log.info(
                "relay_room_evicted",
                room_code=str(room.room_code),
                session_id=str(room.session_id),
                reason="all_peers_disconnected",
            )

    @staticmethod
    def _next_free_slot(room: _Room) -> int:
        for slot in room.slots:
            if not slot.connected:
                return int(slot.slot_index)
        return -1

    @staticmethod
    def _addr_text(addr: PeerAddr) -> str:
        return f"{addr[0]}:{addr[1]}"


__all__ = ["RelayServer", "RelayServerConfig"]
