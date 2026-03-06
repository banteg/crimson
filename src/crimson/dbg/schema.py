from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import msgspec

from ..elapsed_clock import elapsed_field_name as _elapsed_field_name
from ..elapsed_clock import elapsed_ms_value as _elapsed_ms_value
from ..game_modes import GameMode
from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot, TimingSampleRow

TRACE_MAGIC = b"crimson_debug_trace_v1\n"
TRACE_FORMAT_VERSION = 1
TRACE_SCHEMA_VERSION = 8
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


class _TickRecordBase(msgspec.Struct):
    tick_index: int
    dt_ms_i32: int
    mode_id: int
    channels: ReplayTickChannels
    phase_markers: list[str] = msgspec.field(default_factory=list)

    @property
    def elapsed_ms(self) -> int:
        return _elapsed_ms_value(self)

    @property
    def elapsed_field_name(self) -> str:
        return _elapsed_field_name(self)


class SurvivalTickRecord(
    _TickRecordBase,
    kw_only=True,
    tag="survival",
    tag_field="mode",
):
    sim_elapsed_ms: int


class RushTickRecord(
    _TickRecordBase,
    kw_only=True,
    tag="rush",
    tag_field="mode",
):
    raw_frame_elapsed_ms: int


class QuestTickRecord(
    _TickRecordBase,
    kw_only=True,
    tag="quests",
    tag_field="mode",
):
    quest_spawn_timeline_ms: int


type TickRecord = SurvivalTickRecord | RushTickRecord | QuestTickRecord


def build_tick_record_for_mode(
    *,
    mode_id: GameMode | int,
    tick_index: int,
    elapsed_ms: int,
    dt_ms_i32: int,
    channels: ReplayTickChannels,
    phase_markers: list[str] | None = None,
) -> TickRecord:
    mode = GameMode(int(mode_id))
    normalized_phase_markers = list(phase_markers or ())
    if mode == GameMode.RUSH:
        return RushTickRecord(
            tick_index=int(tick_index),
            raw_frame_elapsed_ms=int(elapsed_ms),
            dt_ms_i32=int(dt_ms_i32),
            mode_id=int(mode),
            channels=channels,
            phase_markers=normalized_phase_markers,
        )
    if mode == GameMode.QUESTS:
        return QuestTickRecord(
            tick_index=int(tick_index),
            quest_spawn_timeline_ms=int(elapsed_ms),
            dt_ms_i32=int(dt_ms_i32),
            mode_id=int(mode),
            channels=channels,
            phase_markers=normalized_phase_markers,
        )
    return SurvivalTickRecord(
        tick_index=int(tick_index),
        sim_elapsed_ms=int(elapsed_ms),
        dt_ms_i32=int(dt_ms_i32),
        mode_id=int(mode),
        channels=channels,
        phase_markers=normalized_phase_markers,
    )


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
