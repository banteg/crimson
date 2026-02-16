from __future__ import annotations

from dataclasses import dataclass, field
import logging
import random
import string
import time
import uuid

from .relay_protocol import (
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    RECONNECT_TIMEOUT_MS,
    ClientHello,
    ClientWelcome,
    LegacyLockstepControl,
    LegacyLockstepInputBatch,
    LegacyLockstepTickFrame,
    NetMessage,
    NetcodeMode,
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
    RoomStart,
    RoomState,
    ROOM_CODE_LENGTH,
    StatusSnapshot,
    builds_compatible,
)
from .relay_reliable import RelayReliableLink
from .relay_transport import PeerAddr, RelayUdpTransport


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


def _room_code(rand: random.Random) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(rand.choice(alphabet) for _ in range(int(ROOM_CODE_LENGTH)))


@dataclass(slots=True)
class RelayServerConfig:
    bind_host: str = "0.0.0.0"
    bind_port: int = 31993
    link_timeout_ms: int = LINK_TIMEOUT_MS
    reconnect_timeout_ms: int = RECONNECT_TIMEOUT_MS
    max_rooms: int = 2048


@dataclass(slots=True)
class _Peer:
    addr: PeerAddr
    link: RelayReliableLink = field(default_factory=RelayReliableLink)
    peer_id: str = ""
    build_id: str = ""
    peer_name: str = ""
    room_code: str = ""
    slot_index: int = -1
    last_seen_ms: int = 0


@dataclass(slots=True)
class _RoomSlot:
    slot_index: int
    peer_id: str = ""
    peer_name: str = ""
    ready: bool = False
    reconnect_token: str = ""
    disconnected_ms: int = 0

    @property
    def connected(self) -> bool:
        return bool(self.peer_id)


@dataclass(slots=True)
class _Room:
    room_code: str
    session_id: str
    mode_id: int
    player_count: int
    quest_level: str
    preserve_bugs: bool
    tick_rate: int
    input_delay_ticks: int
    rollback_max_ticks: int
    netcode_mode: NetcodeMode
    status_snapshot: StatusSnapshot | None = None
    started: bool = False
    seed: int = 0
    start_tick: int = 0
    slots: list[_RoomSlot] = field(default_factory=list)

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
    LegacyLockstepTickFrame,
    LegacyLockstepControl,
)


class RelayServer:
    """In-memory UDP relay + invite-code lobby service."""

    def __init__(self, cfg: RelayServerConfig) -> None:
        self.cfg = cfg
        self.transport = RelayUdpTransport(bind_host=str(cfg.bind_host), bind_port=int(cfg.bind_port))
        self._rooms: dict[str, _Room] = {}
        self._peers_by_addr: dict[PeerAddr, _Peer] = {}
        self._peers_by_id: dict[str, _Peer] = {}
        self._room_by_reconnect: dict[str, tuple[str, int]] = {}
        self._rand = random.Random()
        self.log = logging.getLogger("crimson.relay")

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    def open(self) -> None:
        self.transport.open()
        self.log.info("relay_open bind=%s:%d", self.cfg.bind_host, self.bound_port)

    def close(self) -> None:
        self.transport.close()
        self._rooms.clear()
        self._peers_by_addr.clear()
        self._peers_by_id.clear()
        self._room_by_reconnect.clear()
        self.log.info("relay_close")

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
                    continue
                self._handle_client_hello(addr=addr, message=packet.message, now_ms=int(now))
                peer = self._peers_by_addr.get(addr)
                if peer is not None and bool(packet.reliable) and int(packet.seq) > 0:
                    peer.link.prime_recv_seq(int(packet.seq))
                continue

            peer.last_seen_ms = int(now)
            messages, _dup = peer.link.ingest_packet(packet, now_ms=int(now))
            for message in messages:
                self._handle_message(peer=peer, message=message, now_ms=int(now))

        self._poll_resends(now_ms=int(now))
        self._prune_timeouts(now_ms=int(now))

    def _handle_client_hello(self, *, addr: PeerAddr, message: ClientHello, now_ms: int) -> None:
        if int(message.protocol_version) != int(PROTOCOL_VERSION):
            temp = RelayReliableLink()
            packet = temp.build_packet(
                ClientWelcome(
                    accepted=False,
                    reason="protocol_mismatch",
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
        if isinstance(message, Ping):
            self._send_peer(peer, Pong(stamp_ms=int(message.stamp_ms)), reliable=False, now_ms=int(now_ms))
            return

        if isinstance(message, RoomCreate):
            self._handle_room_create(peer=peer, message=message, now_ms=int(now_ms))
            return

        if isinstance(message, RoomJoin):
            self._handle_room_join(peer=peer, message=message, now_ms=int(now_ms))
            return

        if isinstance(message, RoomReady):
            self._handle_room_ready(peer=peer, message=message, now_ms=int(now_ms))
            return

        if isinstance(message, (RbInputBatch, RbResyncRequest, RbResyncBegin, RbResyncChunk, RbResyncCommit)):
            self._forward_room_message(peer=peer, message=message, now_ms=int(now_ms))
            return

        if isinstance(message, (LegacyLockstepInputBatch, LegacyLockstepTickFrame, LegacyLockstepControl)):
            self._forward_room_message(peer=peer, message=message, now_ms=int(now_ms))
            return

    def _handle_room_create(self, *, peer: _Peer, message: RoomCreate, now_ms: int) -> None:
        if peer.room_code:
            self._send_peer(peer, RelayError(reason="already_in_room"), reliable=True, now_ms=int(now_ms))
            return
        if len(self._rooms) >= int(self.cfg.max_rooms):
            self._send_peer(peer, RelayError(reason="room_capacity"), reliable=True, now_ms=int(now_ms))
            return

        code = ""
        for _ in range(32):
            candidate = _room_code(self._rand)
            if candidate in self._rooms:
                continue
            code = candidate
            break
        if not code:
            self._send_peer(peer, RelayError(reason="room_code_exhausted"), reliable=True, now_ms=int(now_ms))
            return

        player_count = max(1, min(4, int(message.player_count)))
        slots = [_RoomSlot(slot_index=i) for i in range(int(player_count))]
        host_slot = slots[0]
        host_slot.peer_id = str(peer.peer_id)
        host_slot.peer_name = str(peer.peer_name)
        host_slot.ready = True
        host_slot.reconnect_token = uuid.uuid4().hex

        room = _Room(
            room_code=str(code),
            session_id=uuid.uuid4().hex[:12],
            mode_id=int(message.mode_id),
            player_count=int(player_count),
            quest_level=str(message.quest_level or ""),
            preserve_bugs=bool(message.preserve_bugs),
            tick_rate=max(1, int(message.tick_rate)),
            input_delay_ticks=max(0, int(message.input_delay_ticks)),
            rollback_max_ticks=max(1, int(message.rollback_max_ticks)),
            netcode_mode=message.netcode_mode,
            status_snapshot=message.status_snapshot,
            slots=slots,
        )
        self._rooms[str(code)] = room
        self._room_by_reconnect[str(host_slot.reconnect_token)] = (str(code), 0)

        peer.room_code = str(code)
        peer.slot_index = 0

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

    def _handle_room_join(self, *, peer: _Peer, message: RoomJoin, now_ms: int) -> None:
        room_code = str(message.room_code or "").upper().strip()
        reconnect_token = str(message.reconnect_token or "").strip()

        if peer.room_code:
            self._send_peer(peer, RelayError(reason="already_in_room"), reliable=True, now_ms=int(now_ms))
            return

        room: _Room | None = None
        slot_index = -1

        if reconnect_token:
            mapping = self._room_by_reconnect.get(str(reconnect_token))
            if mapping is not None:
                room = self._rooms.get(str(mapping[0]))
                slot_index = int(mapping[1])

        if room is None:
            room = self._rooms.get(str(room_code))
            if room is None:
                self._send_peer(peer, RelayError(reason="room_not_found"), reliable=True, now_ms=int(now_ms))
                return
            slot_index = self._next_free_slot(room)
            if slot_index < 0:
                self._send_peer(peer, RelayError(reason="room_full"), reliable=True, now_ms=int(now_ms))
                return

        slot = room.slots[int(slot_index)]
        if slot.peer_id and slot.peer_id != str(peer.peer_id):
            age = max(0, int(now_ms) - int(slot.disconnected_ms or 0))
            if age < int(self.cfg.reconnect_timeout_ms):
                self._send_peer(peer, RelayError(reason="slot_busy"), reliable=True, now_ms=int(now_ms))
                return

        host_slot = room.slots[0]
        host_peer = self._peers_by_id.get(str(host_slot.peer_id))
        if host_peer is not None and host_peer.build_id and peer.build_id:
            if not builds_compatible(str(peer.build_id), str(host_peer.build_id)):
                self._send_peer(peer, RelayError(reason="build_mismatch"), reliable=True, now_ms=int(now_ms))
                return

        slot.peer_id = str(peer.peer_id)
        slot.peer_name = str(peer.peer_name)
        slot.ready = False if not room.started else True
        slot.disconnected_ms = 0
        if not slot.reconnect_token:
            slot.reconnect_token = uuid.uuid4().hex
        self._room_by_reconnect[str(slot.reconnect_token)] = (str(room.room_code), int(slot.slot_index))

        peer.room_code = str(room.room_code)
        peer.slot_index = int(slot.slot_index)

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

        if room.started:
            self._send_room_start(peer=peer, room=room, now_ms=int(now_ms))

    def _handle_room_ready(self, *, peer: _Peer, message: RoomReady, now_ms: int) -> None:
        room = self._rooms.get(str(peer.room_code))
        if room is None:
            self._send_peer(peer, RelayError(reason="not_in_room"), reliable=True, now_ms=int(now_ms))
            return
        slot_index = int(peer.slot_index)
        if slot_index < 0 or slot_index >= len(room.slots):
            self._send_peer(peer, RelayError(reason="bad_slot"), reliable=True, now_ms=int(now_ms))
            return
        slot = room.slots[int(slot_index)]
        if slot.peer_id != str(peer.peer_id):
            self._send_peer(peer, RelayError(reason="slot_owner_mismatch"), reliable=True, now_ms=int(now_ms))
            return
        slot.ready = bool(message.ready)

        if (not room.started) and room.all_ready():
            room.started = True
            room.seed = int((now_ms * 1103515245 + 12345) & 0xFFFFFFFF)
            room.start_tick = 0
            self._broadcast_room_start(room=room, now_ms=int(now_ms))

        self._broadcast_room_state(room=room, now_ms=int(now_ms))

    def _forward_room_message(self, *, peer: _Peer, message: NetMessage, now_ms: int) -> None:
        room = self._rooms.get(str(peer.room_code))
        if room is None:
            self._send_peer(peer, RelayError(reason="not_in_room"), reliable=True, now_ms=int(now_ms))
            return
        reliable = isinstance(message, _FORWARD_RELIABLE_TYPES)
        if isinstance(message, LegacyLockstepInputBatch):
            reliable = False
        for slot in room.slots:
            if (not slot.connected) or slot.peer_id == str(peer.peer_id):
                continue
            dst = self._peers_by_id.get(str(slot.peer_id))
            if dst is None:
                continue
            self._send_peer(dst, message, reliable=bool(reliable), now_ms=int(now_ms))

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
        state = RoomState(
            room_code=str(room.room_code),
            session_id=str(room.session_id),
            mode_id=int(room.mode_id),
            player_count=int(room.player_count),
            quest_level=str(room.quest_level),
            preserve_bugs=bool(room.preserve_bugs),
            tick_rate=int(room.tick_rate),
            input_delay_ticks=int(room.input_delay_ticks),
            rollback_max_ticks=int(room.rollback_max_ticks),
            netcode_mode=room.netcode_mode,
            slots=slots,
            all_ready=bool(room.all_ready()),
            started=bool(room.started),
        )
        for slot in room.slots:
            if not slot.connected:
                continue
            peer = self._peers_by_id.get(str(slot.peer_id))
            if peer is None:
                continue
            self._send_peer(peer, state, reliable=True, now_ms=int(now_ms))

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
        self._send_peer(
            peer,
            RoomStart(
                room_code=str(room.room_code),
                session_id=str(room.session_id),
                seed=int(room.seed),
                start_tick=int(room.start_tick),
                mode_id=int(room.mode_id),
                player_count=int(room.player_count),
                quest_level=str(room.quest_level),
                preserve_bugs=bool(room.preserve_bugs),
                tick_rate=int(room.tick_rate),
                input_delay_ticks=int(room.input_delay_ticks),
                rollback_max_ticks=int(room.rollback_max_ticks),
                netcode_mode=room.netcode_mode,
                slot_index=int(slot_index),
                host_slot_index=0,
                reconnect_token=str(reconnect_token),
                status_snapshot=room.status_snapshot,
            ),
            reliable=True,
            now_ms=int(now_ms),
        )

    def _send_peer(self, peer: _Peer, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        packet = peer.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        self.transport.send_packet(peer.addr, packet)

    def _poll_resends(self, *, now_ms: int) -> None:
        for peer in self._peers_by_id.values():
            for packet in peer.link.poll_resends(now_ms=int(now_ms)):
                self.transport.send_packet(peer.addr, packet)

    def _prune_timeouts(self, *, now_ms: int) -> None:
        timeout = max(250, int(self.cfg.link_timeout_ms))
        for peer_id, peer in list(self._peers_by_id.items()):
            if (int(now_ms) - int(peer.last_seen_ms)) < int(timeout):
                continue
            self._disconnect_peer(peer=peer, reason="timeout", now_ms=int(now_ms))
            self._peers_by_id.pop(str(peer_id), None)
            self._peers_by_addr.pop(peer.addr, None)

    def _disconnect_peer(self, *, peer: _Peer, reason: str, now_ms: int) -> None:
        room = self._rooms.get(str(peer.room_code))
        if room is None:
            return
        if 0 <= int(peer.slot_index) < len(room.slots):
            slot = room.slots[int(peer.slot_index)]
            if slot.peer_id == str(peer.peer_id):
                slot.peer_id = ""
                slot.ready = False
                slot.disconnected_ms = int(now_ms)
                slot.peer_name = ""

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
            self._rooms.pop(str(room.room_code), None)

    @staticmethod
    def _next_free_slot(room: _Room) -> int:
        for slot in room.slots:
            if not slot.connected:
                return int(slot.slot_index)
        return -1


__all__ = ["RelayServer", "RelayServerConfig"]
