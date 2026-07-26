from __future__ import annotations

import math
import zlib
from typing import Literal

import msgspec

from ..quests.types import SpawnEntry
from ..wire.float32_wire import assert_wire_f32, wire_f32
from .relay_protocol import (
    RESYNC_CHUNK_PAYLOAD_BYTES,
    RESYNC_MAX_SNAPSHOT_BYTES,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
)

SCHEMA_VERSION = 4
SNAPSHOT_CODEC = "msgpack_state_v4_f32wire"


class RollbackResyncV5Error(RuntimeError):
    """Raised when rollback resync stream payloads are invalid."""


class ReplayStateSnapshotV2(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int = 0
    recorded_tick_count: int = 0

    def __post_init__(self) -> None:
        self.tick_index = int(self.tick_index)
        self.recorded_tick_count = int(self.recorded_tick_count)


class SurvivalRuntimeSnapshotV2(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0
    perk_pending_count: int = 0

    def __post_init__(self) -> None:
        self.elapsed_ms = wire_f32(float(self.elapsed_ms), field="survival.runtime_state.elapsed_ms")
        self.stage = int(self.stage)
        self.spawn_cooldown_ms = wire_f32(
            float(self.spawn_cooldown_ms),
            field="survival.runtime_state.spawn_cooldown_ms",
        )
        self.perk_pending_count = int(self.perk_pending_count)


class RushRuntimeSnapshotV2(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0
    kill_count: int = 0

    def __post_init__(self) -> None:
        self.elapsed_ms = wire_f32(float(self.elapsed_ms), field="rush.runtime_state.elapsed_ms")
        self.spawn_cooldown_ms = wire_f32(float(self.spawn_cooldown_ms), field="rush.runtime_state.spawn_cooldown_ms")
        self.kill_count = int(self.kill_count)


class QuestsRuntimeSnapshotV2(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: float = 0.0
    spawn_entries: tuple[SpawnEntry, ...] = msgspec.field(default_factory=tuple)
    spawn_timeline_ms: float = 0.0
    no_creatures_timer_ms: float = 0.0
    completion_transition_ms: float = 0.0
    perk_pending_count: int = 0

    def __post_init__(self) -> None:
        self.elapsed_ms = wire_f32(float(self.elapsed_ms), field="quests.runtime_state.elapsed_ms")
        self.spawn_entries = tuple(self.spawn_entries)
        self.spawn_timeline_ms = wire_f32(float(self.spawn_timeline_ms), field="quests.runtime_state.spawn_timeline_ms")
        self.no_creatures_timer_ms = wire_f32(
            float(self.no_creatures_timer_ms),
            field="quests.runtime_state.no_creatures_timer_ms",
        )
        self.completion_transition_ms = wire_f32(
            float(self.completion_transition_ms),
            field="quests.runtime_state.completion_transition_ms",
        )
        self.perk_pending_count = int(self.perk_pending_count)


class _ModeStateSnapshotV2Base(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int = SCHEMA_VERSION
    tick_index: int = 0
    replay_state: ReplayStateSnapshotV2 | None = None

    def __post_init__(self) -> None:
        self.schema_version = int(self.schema_version)
        self.tick_index = int(self.tick_index)


class SurvivalStateSnapshotV2(
    _ModeStateSnapshotV2Base,
    tag="survival",
    tag_field="mode",
):
    runtime_state: SurvivalRuntimeSnapshotV2 = msgspec.field(default_factory=SurvivalRuntimeSnapshotV2)

    @property
    def mode(self) -> Literal["survival"]:
        return "survival"


class RushStateSnapshotV2(
    _ModeStateSnapshotV2Base,
    tag="rush",
    tag_field="mode",
):
    runtime_state: RushRuntimeSnapshotV2 = msgspec.field(default_factory=RushRuntimeSnapshotV2)

    @property
    def mode(self) -> Literal["rush"]:
        return "rush"


class QuestsStateSnapshotV2(
    _ModeStateSnapshotV2Base,
    tag="quests",
    tag_field="mode",
):
    runtime_state: QuestsRuntimeSnapshotV2 = msgspec.field(default_factory=QuestsRuntimeSnapshotV2)

    @property
    def mode(self) -> Literal["quests"]:
        return "quests"


ModeStateSnapshotV2 = SurvivalStateSnapshotV2 | RushStateSnapshotV2 | QuestsStateSnapshotV2


_SNAPSHOT_ENCODER = msgspec.msgpack.Encoder()
_SNAPSHOT_DECODER = msgspec.msgpack.Decoder(type=ModeStateSnapshotV2)


def encode_mode_snapshot(
    *,
    snapshot: ModeStateSnapshotV2,
) -> bytes:
    if int(snapshot.schema_version) != int(SCHEMA_VERSION):
        raise RollbackResyncV5Error("unsupported_snapshot_schema")
    _assert_snapshot_f32(snapshot)
    blob = _SNAPSHOT_ENCODER.encode(snapshot)
    if len(blob) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("snapshot_too_large")
    return blob


def decode_mode_snapshot(blob: bytes) -> ModeStateSnapshotV2:
    if len(blob) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("snapshot_too_large")
    try:
        snapshot = _SNAPSHOT_DECODER.decode(blob)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise RollbackResyncV5Error("snapshot_decode_error") from exc
    if int(snapshot.schema_version) != int(SCHEMA_VERSION):
        raise RollbackResyncV5Error("unsupported_snapshot_schema")
    _assert_snapshot_f32(snapshot)
    return snapshot


def _assert_snapshot_f32(snapshot: ModeStateSnapshotV2) -> None:
    replay_state = snapshot.replay_state
    if replay_state is not None:
        replay_state.tick_index = int(replay_state.tick_index)
        replay_state.recorded_tick_count = int(replay_state.recorded_tick_count)
    match snapshot:
        case SurvivalStateSnapshotV2():
            runtime_state = snapshot.runtime_state
            runtime_state.elapsed_ms = assert_wire_f32(runtime_state.elapsed_ms, field="survival.runtime_state.elapsed_ms")
            runtime_state.spawn_cooldown_ms = assert_wire_f32(
                runtime_state.spawn_cooldown_ms,
                field="survival.runtime_state.spawn_cooldown_ms",
            )
            return
        case RushStateSnapshotV2():
            runtime_state = snapshot.runtime_state
            runtime_state.elapsed_ms = assert_wire_f32(runtime_state.elapsed_ms, field="rush.runtime_state.elapsed_ms")
            runtime_state.spawn_cooldown_ms = assert_wire_f32(
                runtime_state.spawn_cooldown_ms,
                field="rush.runtime_state.spawn_cooldown_ms",
            )
            return
        case QuestsStateSnapshotV2():
            runtime_state = snapshot.runtime_state
            runtime_state.elapsed_ms = assert_wire_f32(runtime_state.elapsed_ms, field="quests.runtime_state.elapsed_ms")
            runtime_state.spawn_entries = tuple(runtime_state.spawn_entries)
            runtime_state.spawn_timeline_ms = assert_wire_f32(
                runtime_state.spawn_timeline_ms,
                field="quests.runtime_state.spawn_timeline_ms",
            )
            runtime_state.no_creatures_timer_ms = assert_wire_f32(
                runtime_state.no_creatures_timer_ms,
                field="quests.runtime_state.no_creatures_timer_ms",
            )
            runtime_state.completion_transition_ms = assert_wire_f32(
                runtime_state.completion_transition_ms,
                field="quests.runtime_state.completion_transition_ms",
            )


class RbResyncMessageSet(msgspec.Struct, frozen=True):
    begin: RbResyncBegin
    chunks: list[RbResyncChunk]
    commit: RbResyncCommit


def build_rb_resync_messages(
    *,
    request_id: str,
    snapshot_tick: int,
    snapshot_blob: bytes,
) -> RbResyncMessageSet:
    payload = bytes(snapshot_blob)
    if len(payload) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("snapshot_too_large")

    compressed = zlib.compress(payload, level=6)
    if len(compressed) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("compressed_snapshot_too_large")

    chunk_size = max(1, int(RESYNC_CHUNK_PAYLOAD_BYTES))
    total_chunks = max(1, int(math.ceil(len(compressed) / float(chunk_size))))

    begin = RbResyncBegin(
        request_id=str(request_id),
        snapshot_tick=int(snapshot_tick),
        codec=SNAPSHOT_CODEC,
        total_chunks=int(total_chunks),
        compressed_size=len(compressed),
        uncompressed_size=len(payload),
    )

    chunks: list[RbResyncChunk] = []
    for chunk_index in range(int(total_chunks)):
        start = int(chunk_index) * int(chunk_size)
        end = start + int(chunk_size)
        chunks.append(
            RbResyncChunk(
                request_id=str(request_id),
                chunk_index=int(chunk_index),
                payload=bytes(compressed[start:end]),
            ),
        )

    commit = RbResyncCommit(
        request_id=str(request_id),
        snapshot_tick=int(snapshot_tick),
    )
    return RbResyncMessageSet(begin=begin, chunks=chunks, commit=commit)


class RbResyncAssemblerV5(msgspec.Struct):
    max_snapshot_bytes: int = RESYNC_MAX_SNAPSHOT_BYTES
    _begin: RbResyncBegin | None = None
    _chunks: dict[int, bytes] = msgspec.field(default_factory=dict)

    @property
    def request_id(self) -> str:
        begin = self._begin
        if begin is None:
            return ""
        return str(begin.request_id or "")

    def begin(self, message: RbResyncBegin) -> None:
        if str(message.codec) != SNAPSHOT_CODEC:
            raise RollbackResyncV5Error("unsupported_snapshot_codec")
        if int(message.compressed_size) < 0 or int(message.compressed_size) > int(self.max_snapshot_bytes):
            raise RollbackResyncV5Error("compressed_snapshot_size_invalid")
        if int(message.uncompressed_size) < 0 or int(message.uncompressed_size) > int(self.max_snapshot_bytes):
            raise RollbackResyncV5Error("snapshot_size_invalid")
        if int(message.total_chunks) <= 0:
            raise RollbackResyncV5Error("resync_chunk_count_invalid")
        self._begin = message
        self._chunks.clear()

    def push_chunk(self, message: RbResyncChunk) -> None:
        begin = self._begin
        if begin is None:
            raise RollbackResyncV5Error("resync_begin_missing")
        if str(message.request_id or "") != str(begin.request_id or ""):
            raise RollbackResyncV5Error("resync_request_id_mismatch")
        index = int(message.chunk_index)
        if index < 0 or index >= int(begin.total_chunks):
            raise RollbackResyncV5Error("resync_chunk_index_invalid")
        self._chunks[index] = bytes(message.payload)

    def finalize(self, message: RbResyncCommit) -> tuple[int, bytes]:
        begin = self._begin
        if begin is None:
            raise RollbackResyncV5Error("resync_begin_missing")
        if str(message.request_id or "") != str(begin.request_id or ""):
            raise RollbackResyncV5Error("resync_request_id_mismatch")
        if int(message.snapshot_tick) != int(begin.snapshot_tick):
            raise RollbackResyncV5Error("resync_tick_mismatch")

        expected_chunks = int(begin.total_chunks)
        if len(self._chunks) != int(expected_chunks):
            raise RollbackResyncV5Error("resync_chunks_incomplete")
        compressed = b"".join(self._chunks[index] for index in range(int(expected_chunks)))
        if len(compressed) != int(begin.compressed_size):
            raise RollbackResyncV5Error("resync_compressed_size_mismatch")
        if len(compressed) > int(self.max_snapshot_bytes):
            raise RollbackResyncV5Error("compressed_snapshot_too_large")

        payload = zlib.decompress(compressed)
        if len(payload) != int(begin.uncompressed_size):
            raise RollbackResyncV5Error("resync_uncompressed_size_mismatch")
        if len(payload) > int(self.max_snapshot_bytes):
            raise RollbackResyncV5Error("snapshot_too_large")

        tick = int(begin.snapshot_tick)
        self._begin = None
        self._chunks.clear()
        return tick, payload


__all__ = [
    "SCHEMA_VERSION",
    "SNAPSHOT_CODEC",
    "ModeStateSnapshotV2",
    "QuestsRuntimeSnapshotV2",
    "QuestsStateSnapshotV2",
    "RbResyncAssemblerV5",
    "RbResyncMessageSet",
    "ReplayStateSnapshotV2",
    "RollbackResyncV5Error",
    "RushRuntimeSnapshotV2",
    "RushStateSnapshotV2",
    "SurvivalRuntimeSnapshotV2",
    "SurvivalStateSnapshotV2",
    "build_rb_resync_messages",
    "decode_mode_snapshot",
    "encode_mode_snapshot",
]
