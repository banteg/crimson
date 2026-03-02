from __future__ import annotations

from collections.abc import Iterable

import msgspec

TRACE_MAGIC = b"crimson_debug_trace_v1\n"
TRACE_FORMAT_VERSION = 1
TRACE_SCHEMA_VERSION = 2
SUPPORTED_TRACE_SCHEMA_VERSIONS = frozenset((TRACE_SCHEMA_VERSION,))

_DEFAULT_CHANNEL_VERSION = 1
_CHANNEL_VERSION_OVERRIDES: dict[str, int] = {}

_CHUNK_KIND_META = b"META"
_CHUNK_KIND_TICK = b"TICK"
_CHUNK_KIND_FOOTER = b"FOTR"
CHUNK_KINDS = frozenset((_CHUNK_KIND_META, _CHUNK_KIND_TICK, _CHUNK_KIND_FOOTER))

CHUNK_KIND_META = _CHUNK_KIND_META.decode("ascii")
CHUNK_KIND_TICK = _CHUNK_KIND_TICK.decode("ascii")
CHUNK_KIND_FOOTER = _CHUNK_KIND_FOOTER.decode("ascii")

TRAILER_MAGIC = b"CDTFTR1\n"

CHUNK_FLAG_ZSTD = 1 << 0
CHUNK_FLAG_MSGPACK = 1 << 1
DEFAULT_CHUNK_FLAGS = int(CHUNK_FLAG_ZSTD | CHUNK_FLAG_MSGPACK)


class TraceMeta(msgspec.Struct):
    trace_format_version: int
    trace_schema_version: int
    created_utc: str
    producer: dict[str, object]
    source: dict[str, object]
    channels: list[str]
    channel_versions: dict[str, int]
    tick_range: dict[str, int]
    config: dict[str, object]


class TickRecord(msgspec.Struct):
    tick_index: int
    elapsed_ms: int
    dt_ms_i32: int | None = None
    mode_id: int = -1
    phase_markers: list[str] = msgspec.field(default_factory=list)
    channels: dict[str, object] = msgspec.field(default_factory=dict)


class TickBlock(msgspec.Struct):
    start_tick: int
    end_tick: int
    ticks: list[TickRecord] = msgspec.field(default_factory=list)


class TickBlockIndexEntry(msgspec.Struct):
    start_tick: int
    end_tick: int
    file_offset: int
    compressed_len: int
    uncompressed_len: int
    checksum: int


class TraceFooter(msgspec.Struct):
    trace_format_version: int
    tick_blocks: list[TickBlockIndexEntry]
    tick_count: int
    first_tick: int | None
    last_tick: int | None
    channel_counts: dict[str, int]


def channel_version_for(channel: str) -> int:
    return int(_CHANNEL_VERSION_OVERRIDES.get(channel, _DEFAULT_CHANNEL_VERSION))


def channel_versions_for(channels: Iterable[str]) -> dict[str, int]:
    return {str(channel): channel_version_for(str(channel)) for channel in channels}
