from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import msgspec

from ..persistence.save_status import GameStatusData
from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot, TimingSampleRow

TRACE_MAGIC = b"crimson_debug_trace_v1\n"
TRACE_FORMAT_VERSION = 1
TRACE_SCHEMA_VERSION = 11
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


class TraceProducer(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    impl: str
    impl_version: str = ""
    platform: str = ""
    arch: str = ""


class TraceSource(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    path: str | None = None
    sha256: str | None = None
    size: int | None = None
    mtime_ns: int | None = None
    kind: str | None = None
    tick_rate: int | None = None
    seed: int | None = None
    mode_id: int | None = None
    quest_level: str | None = None
    run_id: int | None = None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    run_start_seed_source: str | None = None


class TraceChannelVersions(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    checkpoint: int = _DEFAULT_CHANNEL_VERSION
    sim_state: int = _DEFAULT_CHANNEL_VERSION
    entity_samples: int = _DEFAULT_CHANNEL_VERSION
    rng_stream: int = _DEFAULT_CHANNEL_VERSION
    timing_samples: int = _DEFAULT_CHANNEL_VERSION


class TraceTickRange(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    start_tick: int
    end_tick: int
    tick_count: int


class TraceConfig(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    impl: str | None = None
    strict_events: bool | None = None
    zig_build_policy: str | None = None
    zig_exit_code: int | None = None
    zig_stderr_present: bool | None = None
    frida: dict[str, Any] | None = None


class TraceMeta(msgspec.Struct, forbid_unknown_fields=True):
    trace_format_version: int
    trace_schema_version: int
    created_utc: str
    producer: TraceProducer
    source: TraceSource
    channels: list[str]
    channel_versions: TraceChannelVersions
    tick_range: TraceTickRange
    config: TraceConfig
    status: GameStatusData | None = None


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
    channel_tick_counts: dict[str, int]
    channel_row_counts: dict[str, int]


def channel_versions_for(channels: Iterable[str]) -> TraceChannelVersions:
    channel_names = {str(channel) for channel in channels}
    values = {
        channel: int(_DEFAULT_CHANNEL_VERSION)
        for channel in TRACE_REQUIRED_CHANNELS
        if channel in channel_names
    }
    return TraceChannelVersions(**values)
