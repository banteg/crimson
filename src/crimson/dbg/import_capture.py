from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import msgspec

from ..original.capture import convert_capture_to_checkpoints, load_capture
from ..original.schema import CaptureTick
from .checkpoint_codec import checkpoint_to_channel
from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta
from .trace import TraceSummary, write_trace

_ENTITY_KIND_CODES = {
    "creature": 1,
    "projectile": 2,
    "secondary_projectile": 3,
    "bonus": 4,
}


@dataclass(slots=True)
class _EntityUidState:
    generation_by_index: dict[int, int] = field(default_factory=dict)
    active_indices: set[int] = field(default_factory=set)

    def next_uid(self, *, kind: str, index: int, active: bool) -> tuple[int, int]:
        idx = int(index)
        if bool(active) and idx not in self.active_indices:
            self.generation_by_index[idx] = int(self.generation_by_index.get(idx, 0)) + 1
        if bool(active):
            self.active_indices.add(idx)
        else:
            self.active_indices.discard(idx)
        generation = int(self.generation_by_index.get(idx, 0))
        kind_code = int(_ENTITY_KIND_CODES[kind]) & 0xFF
        uid = (kind_code << 56) | ((generation & 0xFFFFFF) << 32) | (idx & 0xFFFFFFFF)
        return int(uid), int(generation)


def _fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def _phase_marker_name(marker: object) -> str:
    builtins_value = msgspec.to_builtins(marker)
    if isinstance(builtins_value, dict):
        marker_type = builtins_value.get("type")
        if marker_type is not None:
            return str(marker_type)
    return str(type(marker).__name__)


def _event_head_kind(head: object) -> str:
    builtins_value = msgspec.to_builtins(head)
    if isinstance(builtins_value, dict):
        marker_type = builtins_value.get("type")
        if marker_type is not None:
            return str(marker_type)
    return str(type(head).__name__)


def _rng_stream_head(rows: list[object]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for row in rows:
        builtins_row = msgspec.to_builtins(row)
        if isinstance(builtins_row, dict):
            out.append(cast(dict[str, object], builtins_row))
    return out


def _entity_channels(
    tick: CaptureTick,
    *,
    creature_state: _EntityUidState,
    projectile_state: _EntityUidState,
    secondary_state: _EntityUidState,
    bonus_state: _EntityUidState,
) -> dict[str, object]:
    creatures: list[dict[str, object]] = []
    for row in tick.samples.creatures:
        payload = cast(dict[str, object], msgspec.to_builtins(row))
        uid, generation = creature_state.next_uid(
            kind="creature",
            index=int(row.index),
            active=bool(int(row.active)),
        )
        payload["uid"] = int(uid)
        payload["generation"] = int(generation)
        payload["pool_kind"] = "creature"
        creatures.append(payload)

    projectiles: list[dict[str, object]] = []
    for row in tick.samples.projectiles:
        payload = cast(dict[str, object], msgspec.to_builtins(row))
        uid, generation = projectile_state.next_uid(
            kind="projectile",
            index=int(row.index),
            active=bool(int(row.active)),
        )
        payload["uid"] = int(uid)
        payload["generation"] = int(generation)
        payload["pool_kind"] = "projectile"
        projectiles.append(payload)

    secondary_projectiles: list[dict[str, object]] = []
    for row in tick.samples.secondary_projectiles:
        payload = cast(dict[str, object], msgspec.to_builtins(row))
        uid, generation = secondary_state.next_uid(
            kind="secondary_projectile",
            index=int(row.index),
            active=bool(int(row.active)),
        )
        payload["uid"] = int(uid)
        payload["generation"] = int(generation)
        payload["pool_kind"] = "secondary_projectile"
        secondary_projectiles.append(payload)

    bonuses: list[dict[str, object]] = []
    for row in tick.samples.bonuses:
        payload = cast(dict[str, object], msgspec.to_builtins(row))
        uid, generation = bonus_state.next_uid(
            kind="bonus",
            index=int(row.index),
            active=bool(int(row.state) != 0),
        )
        payload["uid"] = int(uid)
        payload["generation"] = int(generation)
        payload["pool_kind"] = "bonus"
        bonuses.append(payload)

    return {
        "creatures": creatures,
        "projectiles": projectiles,
        "secondary_projectiles": secondary_projectiles,
        "bonuses": bonuses,
    }


def import_capture_to_trace(
    *,
    capture_path: Path,
    out_path: Path,
    chunk_ticks: int = 256,
) -> TraceSummary:
    capture_path = Path(capture_path)
    out_path = Path(out_path)

    capture = load_capture(capture_path)
    checkpoints = convert_capture_to_checkpoints(capture).checkpoints
    checkpoints_by_tick = {int(checkpoint.tick_index): checkpoint for checkpoint in checkpoints}

    creature_state = _EntityUidState()
    projectile_state = _EntityUidState()
    secondary_state = _EntityUidState()
    bonus_state = _EntityUidState()

    tick_rows: list[TickRecord] = []
    channels_seen: set[str] = set()
    for tick in sorted(capture.ticks, key=lambda row: int(row.tick_index)):
        tick_index = int(tick.tick_index)
        checkpoint = checkpoints_by_tick.get(int(tick_index))
        if checkpoint is None:
            continue

        event_heads = [cast(dict[str, object], msgspec.to_builtins(head)) for head in tick.event_heads]
        micro_traces = [
            cast(dict[str, object], msgspec.to_builtins(head))
            for head in tick.event_heads
            if "creature_update_micro" in _event_head_kind(head)
        ]

        channels = {
            "checkpoint": checkpoint_to_channel(checkpoint),
            "rng_marks": {str(key): int(value) for key, value in sorted(checkpoint.rng_marks.items())},
            "rng_stream_head": _rng_stream_head(list(tick.rng.head)),
            "entity_samples": _entity_channels(
                tick,
                creature_state=creature_state,
                projectile_state=projectile_state,
                secondary_state=secondary_state,
                bonus_state=bonus_state,
            ),
            "event_heads": event_heads,
            "event_counts": cast(dict[str, object], msgspec.to_builtins(tick.event_counts)),
            "micro_traces": micro_traces,
        }
        channels_seen.update(channels.keys())

        phase_markers = [_phase_marker_name(marker) for marker in tick.phase_markers]
        dt_ms_i32 = tick.frame_dt_ms_i32
        if dt_ms_i32 is None:
            dt_ms_i32 = tick.diagnostics.timing.frame_dt_ms_after_i32
        tick_rows.append(
            TickRecord(
                tick_index=int(tick_index),
                elapsed_ms=int(checkpoint.elapsed_ms),
                dt_ms_i32=(None if dt_ms_i32 is None else int(dt_ms_i32)),
                mode_id=int(tick.game_mode_id),
                phase_markers=phase_markers,
                channels=channels,
            ),
        )

    tick_start = min((int(row.tick_index) for row in tick_rows), default=-1)
    tick_end = max((int(row.tick_index) for row in tick_rows), default=-1)
    capture_fingerprint = _fingerprint(capture_path)
    capture_fingerprint["capture_format_version"] = int(capture.capture_format_version)

    config_value = msgspec.to_builtins(capture.config)
    meta = TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": "original_capture",
            "impl_version": "",
            "platform": str(capture.process.platform),
            "arch": str(capture.process.arch),
        },
        source=capture_fingerprint,
        channels=sorted(str(channel) for channel in channels_seen),
        channel_versions={str(channel): 1 for channel in sorted(channels_seen)},
        tick_range={
            "start_tick": int(tick_start),
            "end_tick": int(tick_end),
            "tick_count": int(len(tick_rows)),
        },
        config=(cast(dict[str, object], config_value) if isinstance(config_value, dict) else {}),
    )

    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, int(chunk_ticks)),
    )

