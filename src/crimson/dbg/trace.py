from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import msgspec
import zstandard as zstd

from .schema import (
    CHUNK_FLAG_MSGPACK,
    CHUNK_FLAG_ZSTD,
    CHUNK_KIND_FOOTER,
    CHUNK_KIND_META,
    CHUNK_KIND_TICK,
    CHUNK_KINDS,
    DEFAULT_CHUNK_FLAGS,
    TRACE_FORMAT_VERSION,
    TRACE_MAGIC,
    TRAILER_MAGIC,
    TickBlock,
    TickBlockIndexEntry,
    TickRecord,
    TraceFooter,
    TraceMeta,
)

_FILE_HEADER_STRUCT = struct.Struct("<I")
_CHUNK_HEADER_STRUCT = struct.Struct("<4siiIIIQ")
_TRAILER_STRUCT = struct.Struct("<8sQ")
_META_MAGIC_LEN = len(TRACE_MAGIC)

_ENCODER = msgspec.msgpack.Encoder()
_META_DECODER = msgspec.msgpack.Decoder(type=TraceMeta)
_BLOCK_DECODER = msgspec.msgpack.Decoder(type=TickBlock)
_FOOTER_DECODER = msgspec.msgpack.Decoder(type=TraceFooter)


class TraceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TraceSummary:
    meta: TraceMeta
    footer: TraceFooter


def _checksum64(data: bytes) -> int:
    digest = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(digest, byteorder="little", signed=False)


def _compress(payload: bytes) -> bytes:
    compressor = zstd.ZstdCompressor(level=3)
    return compressor.compress(payload)


def _decompress(payload: bytes) -> bytes:
    decompressor = zstd.ZstdDecompressor()
    return decompressor.decompress(payload)


def _chunk_kind_bytes(kind: str) -> bytes:
    kind_bytes = kind.encode("ascii")
    if kind_bytes not in CHUNK_KINDS:
        raise TraceError(f"unsupported chunk kind: {kind!r}")
    return kind_bytes


def _write_chunk(
    stream: io.BufferedWriter,
    *,
    kind: str,
    start_tick: int,
    end_tick: int,
    payload: bytes,
) -> TickBlockIndexEntry:
    kind_bytes = _chunk_kind_bytes(kind)
    compressed = _compress(payload)
    checksum = _checksum64(payload)
    offset = int(stream.tell())
    header = _CHUNK_HEADER_STRUCT.pack(
        kind_bytes,
        int(start_tick),
        int(end_tick),
        int(DEFAULT_CHUNK_FLAGS),
        int(len(compressed)),
        int(len(payload)),
        int(checksum),
    )
    stream.write(header)
    stream.write(compressed)
    return TickBlockIndexEntry(
        start_tick=int(start_tick),
        end_tick=int(end_tick),
        file_offset=int(offset),
        compressed_len=int(len(compressed)),
        uncompressed_len=int(len(payload)),
        checksum=int(checksum),
    )


def _chunk_payload_from_file(stream: io.BufferedReader, *, offset: int) -> tuple[str, int, int, bytes]:
    stream.seek(int(offset))
    header = stream.read(_CHUNK_HEADER_STRUCT.size)
    if len(header) != _CHUNK_HEADER_STRUCT.size:
        raise TraceError("truncated chunk header")
    kind_bytes, start_tick, end_tick, flags, compressed_len, raw_len, checksum = _CHUNK_HEADER_STRUCT.unpack(header)
    if kind_bytes not in CHUNK_KINDS:
        raise TraceError(f"unknown chunk kind: {kind_bytes!r}")
    payload_compressed = stream.read(int(compressed_len))
    if len(payload_compressed) != int(compressed_len):
        raise TraceError("truncated chunk payload")
    payload = payload_compressed
    if int(flags) & int(CHUNK_FLAG_ZSTD):
        payload = _decompress(payload_compressed)
    if int(flags) & int(CHUNK_FLAG_MSGPACK) == 0:
        raise TraceError("unsupported chunk payload encoding")
    if len(payload) != int(raw_len):
        raise TraceError("chunk size mismatch")
    if _checksum64(payload) != int(checksum):
        raise TraceError("chunk checksum mismatch")
    return kind_bytes.decode("ascii"), int(start_tick), int(end_tick), payload


def write_trace(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Sequence[TickRecord],
    chunk_ticks: int = 256,
) -> TraceSummary:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_ticks = sorted((tick for tick in ticks), key=lambda row: int(row.tick_index))
    chunk_size = max(1, int(chunk_ticks))

    with path.open("wb") as handle:
        handle.write(TRACE_MAGIC)
        handle.write(_FILE_HEADER_STRUCT.pack(int(TRACE_FORMAT_VERSION)))

        _write_chunk(
            handle,
            kind=CHUNK_KIND_META,
            start_tick=-1,
            end_tick=-1,
            payload=_ENCODER.encode(meta),
        )

        tick_indices: list[TickBlockIndexEntry] = []
        channel_counts: dict[str, int] = {}
        for block_start in range(0, len(sorted_ticks), chunk_size):
            block_rows = sorted_ticks[block_start : block_start + chunk_size]
            if not block_rows:
                continue
            block = TickBlock(
                start_tick=int(block_rows[0].tick_index),
                end_tick=int(block_rows[-1].tick_index),
                ticks=list(block_rows),
            )
            tick_indices.append(
                _write_chunk(
                    handle,
                    kind=CHUNK_KIND_TICK,
                    start_tick=int(block.start_tick),
                    end_tick=int(block.end_tick),
                    payload=_ENCODER.encode(block),
                ),
            )
            for row in block_rows:
                for channel_name in row.channels:
                    channel_counts[channel_name] = int(channel_counts.get(channel_name, 0)) + 1

        footer = TraceFooter(
            trace_format_version=int(TRACE_FORMAT_VERSION),
            tick_blocks=tick_indices,
            tick_count=int(len(sorted_ticks)),
            first_tick=(None if not sorted_ticks else int(sorted_ticks[0].tick_index)),
            last_tick=(None if not sorted_ticks else int(sorted_ticks[-1].tick_index)),
            channel_counts={str(key): int(value) for key, value in sorted(channel_counts.items())},
        )
        footer_payload = _ENCODER.encode(footer)
        footer_index = _write_chunk(
            handle,
            kind=CHUNK_KIND_FOOTER,
            start_tick=-1,
            end_tick=-1,
            payload=footer_payload,
        )
        handle.write(
            _TRAILER_STRUCT.pack(
                TRAILER_MAGIC,
                int(footer_index.file_offset),
            ),
        )

    return TraceSummary(meta=meta, footer=footer)


def _load_meta_at_offset(stream: io.BufferedReader, *, offset: int) -> TraceMeta:
    kind, _start, _end, payload = _chunk_payload_from_file(stream, offset=int(offset))
    if str(kind) != CHUNK_KIND_META:
        raise TraceError("invalid trace meta chunk")
    return _META_DECODER.decode(payload)


def _load_footer_and_meta_offsets(path: Path) -> tuple[int, int]:
    path = Path(path)
    with path.open("rb") as handle:
        file_header = handle.read(_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size)
        if len(file_header) != _META_MAGIC_LEN + _FILE_HEADER_STRUCT.size:
            raise TraceError(f"invalid trace file: {path}")
        magic = file_header[:_META_MAGIC_LEN]
        if magic != TRACE_MAGIC:
            raise TraceError(f"unsupported trace magic: {path}")
        (format_version,) = _FILE_HEADER_STRUCT.unpack(file_header[_META_MAGIC_LEN:])
        if int(format_version) != int(TRACE_FORMAT_VERSION):
            raise TraceError(f"unsupported trace format version: {format_version}")

        handle.seek(0, io.SEEK_END)
        end_pos = int(handle.tell())
        if end_pos < (_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size + _TRAILER_STRUCT.size):
            raise TraceError("invalid trace size")
        handle.seek(end_pos - _TRAILER_STRUCT.size)
        trailer_raw = handle.read(_TRAILER_STRUCT.size)
        trailer_magic, footer_offset = _TRAILER_STRUCT.unpack(trailer_raw)
        if trailer_magic != TRAILER_MAGIC:
            raise TraceError("missing trace trailer")
        return int(footer_offset), int(_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size)


def load_trace_meta(path: Path) -> TraceMeta:
    path = Path(path)
    footer_offset, meta_offset = _load_footer_and_meta_offsets(path)
    _ = footer_offset
    with path.open("rb") as handle:
        return _load_meta_at_offset(handle, offset=int(meta_offset))


class TraceReader:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        footer_offset, meta_offset = _load_footer_and_meta_offsets(self.path)
        self._handle = self.path.open("rb")
        self.meta = _load_meta_at_offset(self._handle, offset=int(meta_offset))
        footer_kind, _start, _end, footer_payload = _chunk_payload_from_file(self._handle, offset=int(footer_offset))
        if str(footer_kind) != CHUNK_KIND_FOOTER:
            raise TraceError("invalid trace footer chunk")
        self.footer = _FOOTER_DECODER.decode(footer_payload)
        self._block_cache: dict[int, TickBlock] = {}

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "TraceReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _load_block(self, entry: TickBlockIndexEntry) -> TickBlock:
        cache_key = int(entry.file_offset)
        cached = self._block_cache.get(cache_key)
        if cached is not None:
            return cached
        kind, _start, _end, payload = _chunk_payload_from_file(self._handle, offset=cache_key)
        if str(kind) != CHUNK_KIND_TICK:
            raise TraceError("trace index points at non-tick chunk")
        block = _BLOCK_DECODER.decode(payload)
        self._block_cache[cache_key] = block
        return block

    def tick(self, tick_index: int) -> TickRecord | None:
        tick = int(tick_index)
        for entry in self.footer.tick_blocks:
            if int(entry.start_tick) <= tick <= int(entry.end_tick):
                block = self._load_block(entry)
                for row in block.ticks:
                    if int(row.tick_index) == tick:
                        return row
                return None
        return None

    def iter_ticks(self, *, tick_start: int | None = None, tick_end: int | None = None) -> Iterator[TickRecord]:
        start = None if tick_start is None else int(tick_start)
        end = None if tick_end is None else int(tick_end)
        for entry in self.footer.tick_blocks:
            if start is not None and int(entry.end_tick) < start:
                continue
            if end is not None and int(entry.start_tick) > end:
                continue
            block = self._load_block(entry)
            for row in block.ticks:
                tick = int(row.tick_index)
                if start is not None and tick < start:
                    continue
                if end is not None and tick > end:
                    continue
                yield row

    def all_ticks(self) -> list[TickRecord]:
        return list(self.iter_ticks())


def load_trace(path: Path) -> tuple[TraceMeta, list[TickRecord], TraceFooter]:
    with TraceReader(Path(path)) as trace:
        return trace.meta, trace.all_ticks(), trace.footer


def iter_trace_ticks(path: Path, *, tick_start: int | None = None, tick_end: int | None = None) -> Iterable[TickRecord]:
    with TraceReader(Path(path)) as trace:
        yield from trace.iter_ticks(tick_start=tick_start, tick_end=tick_end)
