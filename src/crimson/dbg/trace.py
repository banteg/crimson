from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Iterable, Iterator, Sequence
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
    SUPPORTED_TRACE_SCHEMA_VERSIONS,
    TRACE_FORMAT_VERSION,
    TRACE_MAGIC,
    TRACE_REQUIRED_CHANNELS,
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
_REPLAY_BLOCK_DECODER = msgspec.msgpack.Decoder(type=TickBlock)
_FOOTER_DECODER = msgspec.msgpack.Decoder(type=TraceFooter)


class TraceError(ValueError):
    pass


class TraceSummary(msgspec.Struct, frozen=True):
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
    offset = stream.tell()
    header = _CHUNK_HEADER_STRUCT.pack(
        kind_bytes,
        start_tick,
        end_tick,
        DEFAULT_CHUNK_FLAGS,
        len(compressed),
        len(payload),
        checksum,
    )
    stream.write(header)
    stream.write(compressed)
    return TickBlockIndexEntry(
        start_tick=start_tick,
        end_tick=end_tick,
        file_offset=offset,
        compressed_len=len(compressed),
        uncompressed_len=len(payload),
        checksum=checksum,
    )


def _write_trace_from_iter(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Iterable[TickRecord],
    chunk_ticks: int,
) -> TraceSummary:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk_size = max(1, int(chunk_ticks))

    with path.open("wb") as handle:
        handle.write(TRACE_MAGIC)
        handle.write(_FILE_HEADER_STRUCT.pack(TRACE_FORMAT_VERSION))

        _write_chunk(
            handle,
            kind=CHUNK_KIND_META,
            start_tick=-1,
            end_tick=-1,
            payload=_ENCODER.encode(meta),
        )

        tick_indices: list[TickBlockIndexEntry] = []
        channel_tick_counts: dict[str, int] = {}
        channel_row_counts: dict[str, int] = {}
        first_tick: int | None = None
        last_tick: int | None = None
        tick_count = 0
        current_block: list[TickRecord] = []

        def flush_block() -> None:
            nonlocal first_tick, last_tick, tick_count
            if not current_block:
                return
            block = TickBlock(
                start_tick=int(current_block[0].tick_index),
                end_tick=int(current_block[-1].tick_index),
                ticks=list(current_block),
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
            for row in current_block:
                row_tick = int(row.tick_index)
                if first_tick is None:
                    first_tick = row_tick
                if last_tick is not None and row_tick < int(last_tick):
                    raise TraceError(
                        f"tick rows must be in non-decreasing order, got {row_tick} after {int(last_tick)}",
                    )
                last_tick = row_tick
                tick_count += 1
                for channel_name in TRACE_REQUIRED_CHANNELS:
                    channel_tick_counts[channel_name] = channel_tick_counts.get(channel_name, 0) + 1
                channel_row_counts["checkpoint"] = channel_row_counts.get("checkpoint", 0) + 1
                channel_row_counts["sim_state"] = channel_row_counts.get("sim_state", 0) + 1
                entity_samples = row.channels.entity_samples
                channel_row_counts["entity_samples"] = channel_row_counts.get("entity_samples", 0) + (
                    len(entity_samples.creatures)
                    + len(entity_samples.projectiles)
                    + len(entity_samples.secondary_projectiles)
                    + len(entity_samples.bonuses)
                )
                channel_row_counts["rng_stream"] = channel_row_counts.get("rng_stream", 0) + len(
                    row.channels.rng_stream,
                )
                channel_row_counts["timing_samples"] = channel_row_counts.get("timing_samples", 0) + len(
                    row.channels.timing_samples,
                )
            current_block.clear()

        for tick in ticks:
            current_block.append(tick)
            if len(current_block) >= int(chunk_size):
                flush_block()
        flush_block()

        if int(tick_count) <= 0:
            raise TraceError("trace must contain at least one tick")
        if first_tick is None or last_tick is None:
            raise TraceError("trace footer tick bounds are missing")
        footer = TraceFooter(
            trace_format_version=TRACE_FORMAT_VERSION,
            tick_blocks=tick_indices,
            tick_count=int(tick_count),
            first_tick=int(first_tick),
            last_tick=int(last_tick),
            channel_tick_counts={key: value for key, value in sorted(channel_tick_counts.items())},
            channel_row_counts={key: value for key, value in sorted(channel_row_counts.items())},
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
                footer_index.file_offset,
            ),
        )

    return TraceSummary(meta=meta, footer=footer)


def write_trace_iter(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Iterable[TickRecord],
    chunk_ticks: int = 256,
) -> TraceSummary:
    return _write_trace_from_iter(
        path,
        meta=meta,
        ticks=ticks,
        chunk_ticks=max(1, int(chunk_ticks)),
    )


def _chunk_payload_from_file(stream: io.BufferedReader, *, offset: int) -> tuple[str, int, int, bytes]:
    stream.seek(offset)
    header = stream.read(_CHUNK_HEADER_STRUCT.size)
    if len(header) != _CHUNK_HEADER_STRUCT.size:
        raise TraceError("truncated chunk header")
    kind_bytes, start_tick, end_tick, flags, compressed_len, raw_len, checksum = _CHUNK_HEADER_STRUCT.unpack(header)
    if kind_bytes not in CHUNK_KINDS:
        raise TraceError(f"unknown chunk kind: {kind_bytes!r}")
    payload_compressed = stream.read(compressed_len)
    if len(payload_compressed) != compressed_len:
        raise TraceError("truncated chunk payload")
    payload = payload_compressed
    if flags & CHUNK_FLAG_ZSTD:
        payload = _decompress(payload_compressed)
    if flags & CHUNK_FLAG_MSGPACK == 0:
        raise TraceError("unsupported chunk payload encoding")
    if len(payload) != raw_len:
        raise TraceError("chunk size mismatch")
    if _checksum64(payload) != checksum:
        raise TraceError("chunk checksum mismatch")
    return kind_bytes.decode("ascii"), start_tick, end_tick, payload


def write_trace(
    path: Path,
    *,
    meta: TraceMeta,
    ticks: Sequence[TickRecord],
    chunk_ticks: int = 256,
) -> TraceSummary:
    sorted_ticks = sorted((tick for tick in ticks), key=lambda row: int(row.tick_index))
    return _write_trace_from_iter(
        path,
        meta=meta,
        ticks=sorted_ticks,
        chunk_ticks=max(1, int(chunk_ticks)),
    )


def _load_meta_at_offset(stream: io.BufferedReader, *, offset: int) -> TraceMeta:
    kind, _start, _end, payload = _chunk_payload_from_file(stream, offset=offset)
    if kind != CHUNK_KIND_META:
        raise TraceError("invalid trace meta chunk")
    meta = _META_DECODER.decode(payload)
    if int(meta.trace_schema_version) not in SUPPORTED_TRACE_SCHEMA_VERSIONS:
        supported = ", ".join(str(version) for version in sorted(SUPPORTED_TRACE_SCHEMA_VERSIONS))
        raise TraceError(
            f"unsupported trace schema version: {meta.trace_schema_version} (supported: {supported})",
        )
    return meta


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
        if format_version != TRACE_FORMAT_VERSION:
            raise TraceError(f"unsupported trace format version: {format_version}")

        handle.seek(0, io.SEEK_END)
        end_pos = handle.tell()
        if end_pos < (_META_MAGIC_LEN + _FILE_HEADER_STRUCT.size + _TRAILER_STRUCT.size):
            raise TraceError("invalid trace size")
        handle.seek(end_pos - _TRAILER_STRUCT.size)
        trailer_raw = handle.read(_TRAILER_STRUCT.size)
        trailer_magic, footer_offset = _TRAILER_STRUCT.unpack(trailer_raw)
        if trailer_magic != TRAILER_MAGIC:
            raise TraceError("missing trace trailer")
        return footer_offset, _META_MAGIC_LEN + _FILE_HEADER_STRUCT.size


def load_trace_meta(path: Path) -> TraceMeta:
    path = Path(path)
    footer_offset, meta_offset = _load_footer_and_meta_offsets(path)
    _ = footer_offset
    with path.open("rb") as handle:
        return _load_meta_at_offset(handle, offset=meta_offset)


class TraceReader:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        footer_offset, meta_offset = _load_footer_and_meta_offsets(self.path)
        self._handle = self.path.open("rb")
        self.meta = _load_meta_at_offset(self._handle, offset=meta_offset)
        footer_kind, _start, _end, footer_payload = _chunk_payload_from_file(self._handle, offset=footer_offset)
        if footer_kind != CHUNK_KIND_FOOTER:
            raise TraceError("invalid trace footer chunk")
        self.footer = _FOOTER_DECODER.decode(footer_payload)
        if int(self.footer.tick_count) <= 0:
            raise TraceError("invalid trace footer tick_count")
        if int(self.footer.first_tick) < 0 or int(self.footer.last_tick) < 0:
            raise TraceError("invalid trace footer tick bounds")
        if int(self.footer.first_tick) > int(self.footer.last_tick):
            raise TraceError("invalid trace footer tick order")
        if len(self.footer.tick_blocks) <= 0:
            raise TraceError("invalid trace footer block index")
        self._block_cache: dict[int, TickBlock] = {}

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> "TraceReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _load_block(self, entry: TickBlockIndexEntry) -> TickBlock:
        cache_key = entry.file_offset
        cached = self._block_cache.get(cache_key)
        if cached is not None:
            return cached
        kind, _start, _end, payload = _chunk_payload_from_file(self._handle, offset=cache_key)
        if kind != CHUNK_KIND_TICK:
            raise TraceError("trace index points at non-tick chunk")
        try:
            block = _REPLAY_BLOCK_DECODER.decode(payload)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise TraceError("invalid replay trace tick payload") from exc
        self._block_cache[cache_key] = block
        return block

    def tick(self, tick_index: int) -> TickRecord | None:
        tick = tick_index
        for entry in self.footer.tick_blocks:
            if entry.start_tick <= tick <= entry.end_tick:
                block = self._load_block(entry)
                for row in block.ticks:
                    if row.tick_index == tick:
                        return row
                return None
        return None

    def iter_ticks(self, *, tick_start: int | None = None, tick_end: int | None = None) -> Iterator[TickRecord]:
        start = tick_start
        end = tick_end
        for entry in self.footer.tick_blocks:
            if start is not None and entry.end_tick < start:
                continue
            if end is not None and entry.start_tick > end:
                continue
            block = self._load_block(entry)
            for row in block.ticks:
                tick = row.tick_index
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
