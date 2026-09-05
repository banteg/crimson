from __future__ import annotations

import msgspec

from ..persistence.save_status import GameStatusData
from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import (
    EntitySamplesSnapshot,
    ReplayStepSnapshot,
    RngStreamRow,
    SimStateSnapshot,
    TimingSampleRow,
)

TRACE_MAGIC = b"crimson_debug_trace_v2\n"
TRACE_FORMAT_VERSION = 2
TRACE_SCHEMA_VERSION = 18

TRACE_REQUIRED_CHANNELS = (
    "replay_step",
    "checkpoint",
    "sim_state",
    "entity_samples",
    "rng_stream",
    "timing_samples",
)

_CHUNK_KIND_META = b"META"
_CHUNK_KIND_TICK = b"TICK"
_CHUNK_KIND_FOOTER = b"FOTR"
CHUNK_KINDS = frozenset((_CHUNK_KIND_META, _CHUNK_KIND_TICK, _CHUNK_KIND_FOOTER))

CHUNK_KIND_META = _CHUNK_KIND_META.decode("ascii")
CHUNK_KIND_TICK = _CHUNK_KIND_TICK.decode("ascii")
CHUNK_KIND_FOOTER = _CHUNK_KIND_FOOTER.decode("ascii")

TRAILER_MAGIC = b"CDTFTR2\n"

CHUNK_FLAG_ZSTD = 1 << 0
CHUNK_FLAG_MSGPACK = 1 << 1
DEFAULT_CHUNK_FLAGS = int(CHUNK_FLAG_MSGPACK)


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
    replay_sha256: str | None = None
    tick_rate: int | None = None
    seed: int | None = None
    mode_id: int | None = None
    player_count: int | None = None
    quest_level: str | None = None
    run_id: int | None = None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    run_start_seed_source: str | None = None


class TraceTickRange(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    start_tick: int
    end_tick: int
    tick_count: int


class TraceMeta(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    trace_format_version: int
    trace_schema_version: int
    created_utc: str
    producer: TraceProducer
    source: TraceSource
    tick_range: TraceTickRange
    status: GameStatusData | None = None


class ReplayTickChannels(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    replay_step: ReplayStepSnapshot
    checkpoint: ReplayCheckpoint
    sim_state: SimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_stream: list[RngStreamRow]
    timing_samples: list[TimingSampleRow]


class TickRecord(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_index: int
    elapsed_ms: int
    dt_ms_i32: int
    mode_id: int
    channels: ReplayTickChannels


class TickBlock(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    start_tick: int
    end_tick: int
    ticks: list[TickRecord]


class TickBlockIndexEntry(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    start_tick: int
    end_tick: int
    file_offset: int
    compressed_len: int
    uncompressed_len: int
    checksum: int


class TraceFooter(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_blocks: list[TickBlockIndexEntry]
    tick_count: int
    first_tick: int
    last_tick: int
