from __future__ import annotations

from typing import Literal

import msgspec

from ..game_modes import GameMode
from ..msgspec_types import NonNegativeInt, PlayerCount, PositiveInt, SignedIndex
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..replay.types import PackedPlayerInput
from .lockstep_protocol import (
    INPUT_STALL_TIMEOUT_MS,
    MAX_PLAYERS,
    RELIABLE_RESEND_MS,
    TICK_RATE,
    build_git_hash,
    build_public_version,
    builds_compatible,
    current_build_id,
)
from .room_code import ROOM_CODE_LENGTH, RoomCode
from .schema_shared import PacketHeader, SlotState

PROTOCOL_VERSION = 6
DEFAULT_PORT = 31993
INPUT_DELAY_TICKS = 1
ROLLBACK_MAX_TICKS = 8
RECONNECT_TIMEOUT_MS = 15_000
LINK_TIMEOUT_MS = 5_000
PING_INTERVAL_MS = 250
RESYNC_CHUNK_PAYLOAD_BYTES = 1_024
RESYNC_MAX_SNAPSHOT_BYTES = 2_097_152

NetcodeMode = Literal["rollback", "lockstep"]


class RelaySlot(SlotState, forbid_unknown_fields=True):
    pass


class ClientHello(msgspec.Struct, tag="client_hello", forbid_unknown_fields=True):
    protocol_version: int = PROTOCOL_VERSION
    build_id: str = ""
    peer_name: str = ""


class ClientWelcome(msgspec.Struct, tag="client_welcome", forbid_unknown_fields=True):
    accepted: bool = False
    reason: str = ""
    protocol_version: int = PROTOCOL_VERSION
    build_id: str = ""
    peer_id: str = ""


class RoomCreate(msgspec.Struct, tag="room_create", forbid_unknown_fields=True):
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: PositiveInt = TICK_RATE
    input_delay_ticks: NonNegativeInt = INPUT_DELAY_TICKS
    rollback_max_ticks: PositiveInt = ROLLBACK_MAX_TICKS
    netcode_mode: NetcodeMode = "rollback"
    status: GameStatusData | None = None


class RoomJoin(msgspec.Struct, tag="room_join", forbid_unknown_fields=True):
    room_code: RoomCode | None = None
    reconnect_token: str = ""


class RoomReady(msgspec.Struct, tag="room_ready", forbid_unknown_fields=True):
    slot_index: int = -1
    ready: bool = False


class RoomState(msgspec.Struct, tag="room_state", forbid_unknown_fields=True):
    room_code: RoomCode
    session_id: str = ""
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: PositiveInt = TICK_RATE
    input_delay_ticks: NonNegativeInt = INPUT_DELAY_TICKS
    rollback_max_ticks: PositiveInt = ROLLBACK_MAX_TICKS
    netcode_mode: NetcodeMode = "rollback"
    slots: list[RelaySlot] = msgspec.field(default_factory=list)
    all_ready: bool = False
    started: bool = False


class RoomStart(msgspec.Struct, tag="room_start", forbid_unknown_fields=True):
    room_code: RoomCode
    session_id: str = ""
    seed: int = 0
    start_tick: NonNegativeInt = 0
    mode_id: GameMode = GameMode.DEMO
    player_count: PlayerCount = 1
    quest_level: QuestLevel | None = None
    preserve_bugs: bool = False
    tick_rate: PositiveInt = TICK_RATE
    input_delay_ticks: NonNegativeInt = INPUT_DELAY_TICKS
    rollback_max_ticks: PositiveInt = ROLLBACK_MAX_TICKS
    netcode_mode: NetcodeMode = "rollback"
    slot_index: SignedIndex = -1
    host_slot_index: NonNegativeInt = 0
    reconnect_token: str = ""
    status: GameStatusData | None = None


class PeerDisconnect(msgspec.Struct, tag="peer_disconnect", forbid_unknown_fields=True):
    slot_index: SignedIndex = -1
    reason: str = ""


class RelayError(msgspec.Struct, tag="relay_error", forbid_unknown_fields=True):
    reason: str = ""


class Ping(msgspec.Struct, tag="ping", forbid_unknown_fields=True):
    stamp_ms: NonNegativeInt = 0


class Pong(msgspec.Struct, tag="pong", forbid_unknown_fields=True):
    stamp_ms: NonNegativeInt = 0


class RbInputSample(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: NonNegativeInt = 0
    packed_input: PackedPlayerInput = msgspec.field(default_factory=list)


class RbInputBatch(msgspec.Struct, tag="rb_input_sample", forbid_unknown_fields=True):
    slot_index: SignedIndex = -1
    samples: list[RbInputSample] = msgspec.field(default_factory=list)


class RbResyncRequest(msgspec.Struct, tag="rb_resync_request", forbid_unknown_fields=True):
    request_id: str = ""
    from_tick: NonNegativeInt = 0
    reason: str = ""
    requested_by_slot: SignedIndex = -1


class RbResyncBegin(msgspec.Struct, tag="rb_resync_begin", forbid_unknown_fields=True):
    request_id: str = ""
    snapshot_tick: NonNegativeInt = 0
    codec: str = "msgpack_state_v1"
    total_chunks: NonNegativeInt = 0
    compressed_size: NonNegativeInt = 0
    uncompressed_size: NonNegativeInt = 0


class RbResyncChunk(msgspec.Struct, tag="rb_resync_chunk", forbid_unknown_fields=True):
    request_id: str = ""
    chunk_index: NonNegativeInt = 0
    payload: bytes = b""


class RbResyncCommit(msgspec.Struct, tag="rb_resync_commit", forbid_unknown_fields=True):
    request_id: str = ""
    snapshot_tick: NonNegativeInt = 0


class LockstepInputBatch(msgspec.Struct, tag="lockstep_state_input_batch", forbid_unknown_fields=True):
    payload: bytes = b""


class LockstepTickFrame(msgspec.Struct, tag="lockstep_state_tick_frame", forbid_unknown_fields=True):
    payload: bytes = b""


class LockstepControl(msgspec.Struct, tag="lockstep_state_control", forbid_unknown_fields=True):
    payload: bytes = b""


type NetMessage = (
    ClientHello
    | ClientWelcome
    | RoomCreate
    | RoomJoin
    | RoomReady
    | RoomState
    | RoomStart
    | PeerDisconnect
    | RelayError
    | Ping
    | Pong
    | RbInputBatch
    | RbResyncRequest
    | RbResyncBegin
    | RbResyncChunk
    | RbResyncCommit
    | LockstepInputBatch
    | LockstepTickFrame
    | LockstepControl
)


class RelayPacket(PacketHeader, forbid_unknown_fields=True):
    message: NetMessage = msgspec.field(default_factory=Ping)


_PACKET_DECODER = msgspec.msgpack.Decoder(type=RelayPacket)


def encode_packet(packet: RelayPacket) -> bytes:
    return msgspec.msgpack.encode(packet)


def decode_packet(blob: bytes) -> RelayPacket:
    return _PACKET_DECODER.decode(blob)


__all__ = [
    "DEFAULT_PORT",
    "INPUT_DELAY_TICKS",
    "INPUT_STALL_TIMEOUT_MS",
    "LINK_TIMEOUT_MS",
    "MAX_PLAYERS",
    "PING_INTERVAL_MS",
    "PROTOCOL_VERSION",
    "RECONNECT_TIMEOUT_MS",
    "RELIABLE_RESEND_MS",
    "RESYNC_CHUNK_PAYLOAD_BYTES",
    "RESYNC_MAX_SNAPSHOT_BYTES",
    "ROLLBACK_MAX_TICKS",
    "ROOM_CODE_LENGTH",
    "TICK_RATE",
    "ClientHello",
    "ClientWelcome",
    "LockstepControl",
    "LockstepInputBatch",
    "LockstepTickFrame",
    "NetMessage",
    "NetcodeMode",
    "PeerDisconnect",
    "Ping",
    "Pong",
    "RbInputBatch",
    "RbInputSample",
    "RbResyncBegin",
    "RbResyncChunk",
    "RbResyncCommit",
    "RbResyncRequest",
    "RelayError",
    "RelayPacket",
    "RelaySlot",
    "RoomCreate",
    "RoomJoin",
    "RoomReady",
    "RoomStart",
    "RoomState",
    "build_git_hash",
    "build_public_version",
    "builds_compatible",
    "current_build_id",
    "decode_packet",
    "encode_packet",
]
