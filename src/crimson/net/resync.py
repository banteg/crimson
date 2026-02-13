from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import zlib

import msgspec

from .protocol import ResyncBegin, ResyncChunk, ResyncCommit


class ResyncBuildError(ValueError):
    pass


class _ResyncPayload(msgspec.Struct, forbid_unknown_fields=True):
    replay_blob: bytes
    checkpoints_blob: bytes


def _split_chunks(payload: bytes, *, chunk_size: int) -> list[bytes]:
    if int(chunk_size) <= 0:
        raise ResyncBuildError(f"chunk_size must be positive, got {chunk_size}")
    out: list[bytes] = []
    for offset in range(0, len(payload), int(chunk_size)):
        out.append(payload[offset : offset + int(chunk_size)])
    if not out:
        out.append(b"")
    return out


def build_resync_messages(
    *,
    replay_blob: bytes,
    checkpoints_blob: bytes,
    tick_index: int,
    chunk_size: int = 32_768,
    stream_id: str | None = None,
) -> tuple[ResyncBegin, list[ResyncChunk], ResyncCommit]:
    payload = _ResyncPayload(
        replay_blob=bytes(replay_blob),
        checkpoints_blob=bytes(checkpoints_blob),
    )
    packed = msgspec.msgpack.encode(payload)
    compressed = zlib.compress(packed, level=9)
    chunks_raw = _split_chunks(compressed, chunk_size=int(chunk_size))
    resolved_stream_id = str(stream_id or secrets.token_hex(8))

    begin = ResyncBegin(
        stream_id=resolved_stream_id,
        total_chunks=int(len(chunks_raw)),
        compressed_size=int(len(compressed)),
        replay_size=int(len(replay_blob)),
        checkpoints_size=int(len(checkpoints_blob)),
    )
    chunks = [
        ResyncChunk(
            stream_id=resolved_stream_id,
            chunk_index=int(idx),
            payload=bytes(chunk),
        )
        for idx, chunk in enumerate(chunks_raw)
    ]
    commit = ResyncCommit(
        stream_id=resolved_stream_id,
        tick_index=int(tick_index),
    )
    return begin, chunks, commit


@dataclass(slots=True)
class ResyncAssembler:
    begin_message: ResyncBegin | None = None
    _chunks: dict[int, bytes] = field(default_factory=dict)
    _committed_tick: int | None = None

    @property
    def stream_id(self) -> str:
        begin = self.begin_message
        if begin is None:
            return ""
        return str(begin.stream_id)

    def reset(self) -> None:
        self.begin_message = None
        self._chunks.clear()
        self._committed_tick = None

    def ingest_begin(self, begin: ResyncBegin) -> None:
        self.begin_message = begin
        self._chunks.clear()
        self._committed_tick = None

    def ingest_chunk(self, chunk: ResyncChunk) -> bool:
        begin = self.begin_message
        if begin is None:
            return False
        if str(chunk.stream_id) != str(begin.stream_id):
            return False
        idx = int(chunk.chunk_index)
        if idx < 0 or idx >= int(begin.total_chunks):
            return False
        self._chunks[idx] = bytes(chunk.payload)
        return True

    def ingest_commit(self, commit: ResyncCommit) -> bool:
        begin = self.begin_message
        if begin is None:
            return False
        if str(commit.stream_id) != str(begin.stream_id):
            return False
        self._committed_tick = int(commit.tick_index)
        return True

    def ready(self) -> bool:
        begin = self.begin_message
        if begin is None:
            return False
        if self._committed_tick is None:
            return False
        return len(self._chunks) == int(begin.total_chunks)

    def rebuild_payload(self) -> tuple[bytes, bytes, int]:
        begin = self.begin_message
        if begin is None:
            raise ResyncBuildError("missing resync_begin")
        if self._committed_tick is None:
            raise ResyncBuildError("missing resync_commit")
        if len(self._chunks) != int(begin.total_chunks):
            raise ResyncBuildError(
                f"missing chunks: have={len(self._chunks)} expected={int(begin.total_chunks)}"
            )

        ordered = b"".join(self._chunks[idx] for idx in range(int(begin.total_chunks)))
        if len(ordered) != int(begin.compressed_size):
            raise ResyncBuildError(
                f"compressed size mismatch: have={len(ordered)} expected={int(begin.compressed_size)}"
            )
        packed = zlib.decompress(ordered)
        payload = msgspec.msgpack.decode(packed, type=_ResyncPayload)
        if len(payload.replay_blob) != int(begin.replay_size):
            raise ResyncBuildError(
                f"replay size mismatch: have={len(payload.replay_blob)} expected={int(begin.replay_size)}"
            )
        if len(payload.checkpoints_blob) != int(begin.checkpoints_size):
            raise ResyncBuildError(
                f"checkpoint size mismatch: have={len(payload.checkpoints_blob)} expected={int(begin.checkpoints_size)}"
            )
        return (
            bytes(payload.replay_blob),
            bytes(payload.checkpoints_blob),
            int(self._committed_tick),
        )
