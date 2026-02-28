from __future__ import annotations

import hashlib
import math
import zlib
from typing import Any, Literal

import msgspec

from .relay_protocol import (
    RESYNC_CHUNK_PAYLOAD_BYTES,
    RESYNC_MAX_SNAPSHOT_BYTES,
    RbResyncBegin,
    RbResyncChunk,
    RbResyncCommit,
)

SCHEMA_VERSION = 1
SNAPSHOT_CODEC = "msgpack_state_v1"


class RollbackResyncV5Error(RuntimeError):
    """Raised when rollback resync stream payloads are invalid."""


class ModeStateSnapshotV1(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int = SCHEMA_VERSION
    mode: Literal["survival", "rush", "quests"] = "survival"
    tick_index: int = 0
    session_state: dict[str, Any] = msgspec.field(default_factory=dict)
    mode_state: dict[str, Any] = msgspec.field(default_factory=dict)
    replay_state: dict[str, Any] | None = None


_SNAPSHOT_ENCODER = msgspec.msgpack.Encoder()
_SNAPSHOT_DECODER = msgspec.msgpack.Decoder(type=ModeStateSnapshotV1)


def _sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def encode_mode_snapshot(
    *,
    mode: Literal["survival", "rush", "quests"],
    tick_index: int,
    session_state: dict[str, Any],
    mode_state: dict[str, Any],
    replay_state: dict[str, Any] | None = None,
) -> bytes:
    snapshot = ModeStateSnapshotV1(
        schema_version=SCHEMA_VERSION,
        mode=mode,
        tick_index=int(tick_index),
        session_state=dict(session_state),
        mode_state=dict(mode_state),
        replay_state=(None if replay_state is None else dict(replay_state)),
    )
    blob = _SNAPSHOT_ENCODER.encode(snapshot)
    if len(blob) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("snapshot_too_large")
    return blob


def decode_mode_snapshot(blob: bytes) -> ModeStateSnapshotV1:
    if len(blob) > int(RESYNC_MAX_SNAPSHOT_BYTES):
        raise RollbackResyncV5Error("snapshot_too_large")
    snapshot = _SNAPSHOT_DECODER.decode(blob)
    if int(snapshot.schema_version) != int(SCHEMA_VERSION):
        raise RollbackResyncV5Error("unsupported_snapshot_schema")
    return snapshot


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
    digest = _sha256_hex(payload)

    begin = RbResyncBegin(
        request_id=str(request_id),
        snapshot_tick=int(snapshot_tick),
        codec=SNAPSHOT_CODEC,
        total_chunks=int(total_chunks),
        compressed_size=int(len(compressed)),
        uncompressed_size=int(len(payload)),
        payload_sha256=str(digest),
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
        payload_sha256=str(digest),
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
        if str(message.payload_sha256 or "") != str(begin.payload_sha256 or ""):
            raise RollbackResyncV5Error("resync_sha_mismatch")

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

        digest = _sha256_hex(payload)
        if digest != str(begin.payload_sha256 or ""):
            raise RollbackResyncV5Error("resync_sha_mismatch")

        tick = int(begin.snapshot_tick)
        self._begin = None
        self._chunks.clear()
        return tick, payload


__all__ = [
    "ModeStateSnapshotV1",
    "RbResyncAssemblerV5",
    "RbResyncMessageSet",
    "RollbackResyncV5Error",
    "SCHEMA_VERSION",
    "SNAPSHOT_CODEC",
    "build_rb_resync_messages",
    "decode_mode_snapshot",
    "encode_mode_snapshot",
]
