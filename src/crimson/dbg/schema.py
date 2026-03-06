from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot, TimingSampleRow

TRACE_MAGIC = b"crimson_debug_trace_v1\n"
TRACE_FORMAT_VERSION = 1
TRACE_SCHEMA_VERSION = 7
SUPPORTED_TRACE_SCHEMA_VERSIONS = frozenset((TRACE_SCHEMA_VERSION,))

TRACE_REQUIRED_CHANNELS = (
    "checkpoint",
    "sim_state",
    "entity_samples",
    "rng_stream",
    "timing_samples",
)

_DEFAULT_CHANNEL_VERSION = 1

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
    producer: dict[str, Any]
    source: dict[str, Any]
    channels: list[str]
    channel_versions: dict[str, int]
    tick_range: dict[str, int]
    config: dict[str, Any]


class ReplayTickChannels(msgspec.Struct):
    checkpoint: ReplayCheckpoint
    sim_state: SimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_stream: list[RngStreamRow] = msgspec.field(default_factory=list)
    timing_samples: list[TimingSampleRow] = msgspec.field(default_factory=list)


class TickRecord(msgspec.Struct):
    tick_index: int
    elapsed_ms: int
    dt_ms_i32: int
    mode_id: int
    channels: ReplayTickChannels
    phase_markers: list[str] = msgspec.field(default_factory=list)


class TickBlock(msgspec.Struct):
    start_tick: int
    end_tick: int
    ticks: list[TickRecord]


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
    first_tick: int
    last_tick: int
    channel_counts: dict[str, int]


def channel_versions_for(channels: Iterable[str]) -> dict[str, int]:
    return {str(channel): int(_DEFAULT_CHANNEL_VERSION) for channel in channels}
