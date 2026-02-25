from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import msgspec

from ..replay import load_replay_file
from ..replay.checkpoints import ReplayCheckpoint
from ..sim.driver.replay_runner import run_replay
from ..sim.driver.setup import ReplayRunnerError
from ..sim.world_state import WorldState
from .checkpoint_codec import checkpoint_to_channel
from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta
from .trace import TraceSummary, write_trace

RecordProfile = Literal["minimal", "standard", "full"]

_ENTITY_KIND_CODES = {
    "creature": 1,
    "projectile": 2,
    "secondary_projectile": 3,
    "bonus": 4,
}

_CRT_RAND_MULT = 214013
_CRT_RAND_INC = 2531011
_CRT_RAND_MASK = 0xFFFFFFFF
_CRT_RAND_CALL_SEARCH_LIMIT = 4096


@dataclass(slots=True)
class _EntityUidState:
    generation_by_index: dict[int, int] = field(default_factory=dict)
    active_indices: set[int] = field(default_factory=set)
    _seen_in_tick: set[int] = field(default_factory=set)

    def begin_tick(self) -> None:
        self._seen_in_tick.clear()

    def end_tick(self) -> None:
        self.active_indices = set(self._seen_in_tick)

    def next_uid(self, *, kind: str, index: int) -> tuple[int, int]:
        idx = int(index)
        if idx not in self.active_indices:
            self.generation_by_index[idx] = int(self.generation_by_index.get(idx, 0)) + 1
        self._seen_in_tick.add(idx)
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


def _coerce_int(value: object, *, default: int = -1) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _coerce_float(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _dict_str_object(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
    return out


def _state_mark(marks: dict[str, int], key: str) -> int | None:
    if key not in marks:
        return None
    value = _coerce_int(marks.get(key), default=-1)
    if value < 0:
        return None
    return int(value)


def _infer_rand_calls_between_states(before_state: int, after_state: int, *, max_calls: int) -> int | None:
    before = int(before_state) & _CRT_RAND_MASK
    after = int(after_state) & _CRT_RAND_MASK
    if before == after:
        return 0
    state = int(before)
    for idx in range(1, max(0, int(max_calls)) + 1):
        state = (state * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        if state == after:
            return int(idx)
    return None


def _rng_stream_head_from_checkpoint(checkpoint: ReplayCheckpoint, *, max_rows: int = 128) -> list[dict[str, object]]:
    marks = checkpoint.rng_marks
    before_state = _state_mark(marks, "before_events")
    if before_state is None:
        before_state = _state_mark(marks, "before_world_step")
    after_state = _state_mark(marks, "after_post_events")
    if after_state is None:
        after_state = _state_mark(marks, "after_events")
    if after_state is None:
        after_state = _state_mark(marks, "after_world_step")
    if before_state is None or after_state is None:
        return []

    total_calls = _infer_rand_calls_between_states(
        int(before_state),
        int(after_state),
        max_calls=_CRT_RAND_CALL_SEARCH_LIMIT,
    )
    if total_calls is None:
        return []

    limit = min(max(0, int(total_calls)), max(0, int(max_rows)))
    state = int(before_state) & _CRT_RAND_MASK
    rows: list[dict[str, object]] = []
    for call_index in range(limit):
        state_before_u32 = int(state) & _CRT_RAND_MASK
        state_after_u32 = (int(state_before_u32) * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        rows.append(
            {
                "tick_call_index": int(call_index) + 1,
                "value_15": int((state_after_u32 >> 16) & 0x7FFF),
                "state_before_u32": int(state_before_u32),
                "state_after_u32": int(state_after_u32),
                "caller_static": None,
                "branch_id": None,
                "inferred": True,
            },
        )
        state = int(state_after_u32)
    return rows


def _event_heads_from_checkpoint(checkpoint: ReplayCheckpoint) -> list[dict[str, object]]:
    heads: list[dict[str, object]] = [
        {
            "type": "event_summary",
            "hit_count": int(checkpoint.events.hit_count),
            "pickup_count": int(checkpoint.events.pickup_count),
            "sfx_count": int(checkpoint.events.sfx_count),
        },
    ]
    for entry in checkpoint.deaths:
        heads.append(
            {
                "type": "creature_death",
                "creature_index": int(entry.creature_index),
                "type_id": int(entry.type_id),
                "reward_value": float(entry.reward_value),
                "xp_awarded": int(entry.xp_awarded),
                "owner_id": int(entry.owner_id),
            },
        )
    for sfx_key in checkpoint.events.sfx_head:
        heads.append({"type": "sfx", "key": str(sfx_key)})
    if int(checkpoint.perk.pending_count) > 0 or bool(checkpoint.perk.choices_dirty):
        heads.append(
            {
                "type": "perk_state",
                "pending_count": int(checkpoint.perk.pending_count),
                "choices_dirty": bool(checkpoint.perk.choices_dirty),
                "choices_count": int(len(checkpoint.perk.choices)),
            },
        )
    return heads


def _creature_map(entity_samples: dict[str, object] | None) -> dict[int, dict[str, object]]:
    if entity_samples is None:
        return {}
    creatures_obj = entity_samples.get("creatures")
    if not isinstance(creatures_obj, list):
        return {}
    out: dict[int, dict[str, object]] = {}
    for item in creatures_obj:
        mapped = _dict_str_object(item)
        if mapped is None:
            continue
        uid = _coerce_int(mapped.get("uid"), default=-1)
        if uid < 0:
            continue
        out[int(uid)] = mapped
    return out


def _micro_traces_from_entities(
    *,
    previous_samples: dict[str, object] | None,
    current_samples: dict[str, object] | None,
) -> list[dict[str, object]]:
    if previous_samples is None or current_samples is None:
        return []

    prev_creatures = _creature_map(previous_samples)
    curr_creatures = _creature_map(current_samples)
    rows: list[dict[str, object]] = []
    for uid in sorted(set(prev_creatures) & set(curr_creatures)):
        prev_row = prev_creatures[int(uid)]
        curr_row = curr_creatures[int(uid)]
        prev_pos = _dict_str_object(prev_row.get("pos")) or {}
        curr_pos = _dict_str_object(curr_row.get("pos")) or {}
        px = _coerce_float(prev_pos.get("x"))
        py = _coerce_float(prev_pos.get("y"))
        cx = _coerce_float(curr_pos.get("x"))
        cy = _coerce_float(curr_pos.get("y"))
        dx = float(cx - px)
        dy = float(cy - py)
        rows.append(
            {
                "type": "creature_update_micro_window",
                "uid": int(uid),
                "index": _coerce_int(curr_row.get("index"), default=-1),
                "before_pos": {"x": float(px), "y": float(py)},
                "after_pos": {"x": float(cx), "y": float(cy)},
                "dx": float(dx),
                "dy": float(dy),
                "before_hp": _coerce_float(prev_row.get("hp")),
                "after_hp": _coerce_float(curr_row.get("hp")),
                "before_heading": _coerce_float(prev_row.get("heading")),
                "after_heading": _coerce_float(curr_row.get("heading")),
            },
        )
    return rows


def _entity_samples_for_world(
    world: WorldState,
    *,
    creature_state: _EntityUidState,
    projectile_state: _EntityUidState,
    secondary_state: _EntityUidState,
    bonus_state: _EntityUidState,
) -> dict[str, object]:
    creature_state.begin_tick()
    projectile_state.begin_tick()
    secondary_state.begin_tick()
    bonus_state.begin_tick()

    creatures: list[dict[str, object]] = []
    for index, creature in enumerate(world.creatures.entries):
        if not creature.active:
            continue
        uid, generation = creature_state.next_uid(kind="creature", index=int(index))
        creatures.append(
            {
                "uid": int(uid),
                "generation": int(generation),
                "pool_kind": "creature",
                "index": int(index),
                "active": True,
                "type_id": int(creature.type_id),
                "hp": float(creature.hp),
                "pos": {"x": float(creature.pos.x), "y": float(creature.pos.y)},
                "flags": int(creature.flags),
                "ai_mode": int(creature.ai_mode),
                "link_index": int(creature.link_index),
                "heading": float(creature.heading),
                "target_heading": float(creature.target_heading),
                "orbit_angle": float(creature.orbit_angle),
                "orbit_radius": float(creature.orbit_radius),
                "lifecycle_stage": float(creature.lifecycle_stage),
            },
        )

    projectiles: list[dict[str, object]] = []
    for index, projectile in enumerate(world.state.projectiles.entries):
        if not projectile.active:
            continue
        uid, generation = projectile_state.next_uid(kind="projectile", index=int(index))
        projectiles.append(
            {
                "uid": int(uid),
                "generation": int(generation),
                "pool_kind": "projectile",
                "index": int(index),
                "active": True,
                "type_id": int(projectile.type_id),
                "angle": float(projectile.angle),
                "pos": {"x": float(projectile.pos.x), "y": float(projectile.pos.y)},
                "vel": {"x": float(projectile.vel.x), "y": float(projectile.vel.y)},
                "life_timer": float(projectile.life_timer),
                "speed_scale": float(projectile.speed_scale),
                "damage_pool": float(projectile.damage_pool),
                "hit_radius": float(projectile.hit_radius),
                "base_damage": float(projectile.base_damage),
                "owner_id": int(projectile.owner_id),
            },
        )

    secondary_projectiles: list[dict[str, object]] = []
    for index, projectile in enumerate(world.state.secondary_projectiles.entries):
        if not projectile.active:
            continue
        uid, generation = secondary_state.next_uid(kind="secondary_projectile", index=int(index))
        secondary_projectiles.append(
            {
                "uid": int(uid),
                "generation": int(generation),
                "pool_kind": "secondary_projectile",
                "index": int(index),
                "active": True,
                "type_id": int(projectile.type_id),
                "angle": float(projectile.angle),
                "pos": {"x": float(projectile.pos.x), "y": float(projectile.pos.y)},
                "vel": {"x": float(projectile.vel.x), "y": float(projectile.vel.y)},
                "speed": float(projectile.speed),
                "trail_timer": float(projectile.trail_timer),
                "owner_id": int(projectile.owner_id),
                "target_id": int(projectile.target_id),
            },
        )

    bonuses: list[dict[str, object]] = []
    for index, bonus in enumerate(world.state.bonus_pool.entries):
        if int(bonus.bonus_id) == 0:
            continue
        uid, generation = bonus_state.next_uid(kind="bonus", index=int(index))
        bonuses.append(
            {
                "uid": int(uid),
                "generation": int(generation),
                "pool_kind": "bonus",
                "index": int(index),
                "bonus_id": int(bonus.bonus_id),
                "picked": bool(bonus.picked),
                "time_left": float(bonus.time_left),
                "time_max": float(bonus.time_max),
                "pos": {"x": float(bonus.pos.x), "y": float(bonus.pos.y)},
                "amount": int(bonus.amount),
            },
        )

    creature_state.end_tick()
    projectile_state.end_tick()
    secondary_state.end_tick()
    bonus_state.end_tick()

    return {
        "creatures": creatures,
        "projectiles": projectiles,
        "secondary_projectiles": secondary_projectiles,
        "bonuses": bonuses,
    }


def record_replay_to_trace(
    *,
    replay_path: Path,
    out_path: Path,
    profile: RecordProfile = "standard",
    max_ticks: int | None = None,
    strict_events: bool = True,
    chunk_ticks: int = 256,
) -> TraceSummary:
    replay_path = Path(replay_path)
    out_path = Path(out_path)
    replay = load_replay_file(replay_path)

    replay_tick_count = len(replay.inputs)
    tick_count = replay_tick_count if max_ticks is None else min(replay_tick_count, max(0, int(max_ticks)))
    checkpoint_ticks = set(range(tick_count))
    checkpoints: list[ReplayCheckpoint] = []

    include_rng = profile in {"standard", "full"}
    include_entities = profile in {"standard", "full"}
    include_full_event_channels = profile == "full"
    trace_rng = profile in {"standard", "full"}

    entity_samples_by_tick: dict[int, dict[str, object]] = {}
    creature_state = _EntityUidState()
    projectile_state = _EntityUidState()
    secondary_state = _EntityUidState()
    bonus_state = _EntityUidState()

    def _tick_observer(tick_index: int, world: WorldState) -> None:
        if not include_entities:
            return
        entity_samples_by_tick[int(tick_index)] = _entity_samples_for_world(
            world,
            creature_state=creature_state,
            projectile_state=projectile_state,
            secondary_state=secondary_state,
            bonus_state=bonus_state,
        )

    try:
        run_replay(
            replay,
            max_ticks=(None if max_ticks is None else int(max_ticks)),
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoints_out=checkpoints,
            checkpoint_ticks=checkpoint_ticks,
            tick_observer=_tick_observer,
        )
    except ReplayRunnerError as exc:
        raise ValueError(f"replay recording failed: {exc}") from exc

    tick_rows: list[TickRecord] = []
    channels_seen: set[str] = set()
    previous_entity_samples: dict[str, object] | None = None
    for checkpoint in sorted(checkpoints, key=lambda row: int(row.tick_index)):
        tick_index = int(checkpoint.tick_index)
        channels: dict[str, object] = {
            "checkpoint": checkpoint_to_channel(checkpoint),
        }
        if include_rng:
            channels["rng_marks"] = {str(key): int(value) for key, value in sorted(checkpoint.rng_marks.items())}
            channels["rng_stream_head"] = _rng_stream_head_from_checkpoint(checkpoint)

        entity_samples: dict[str, object] | None = None
        if include_entities:
            entity_samples_obj = entity_samples_by_tick.get(tick_index)
            entity_samples = (
                dict(entity_samples_obj)
                if isinstance(entity_samples_obj, dict)
                else None
            )
            if entity_samples is not None:
                channels["entity_samples"] = entity_samples
        if include_full_event_channels:
            channels["event_heads"] = _event_heads_from_checkpoint(checkpoint)
            channels["event_summary"] = msgspec.to_builtins(checkpoint.events)
            channels["perk_snapshot"] = msgspec.to_builtins(checkpoint.perk)
            channels["micro_traces"] = _micro_traces_from_entities(
                previous_samples=previous_entity_samples,
                current_samples=entity_samples,
            )

        channels_seen.update(channels.keys())
        tick_rows.append(
            TickRecord(
                tick_index=int(tick_index),
                elapsed_ms=int(checkpoint.elapsed_ms),
                dt_ms_i32=None,
                mode_id=int(replay.header.game_mode_id),
                phase_markers=[],
                channels=channels,
            ),
        )
        if entity_samples is not None:
            previous_entity_samples = entity_samples

    tick_start = min((int(row.tick_index) for row in tick_rows), default=-1)
    tick_end = max((int(row.tick_index) for row in tick_rows), default=-1)
    replay_fingerprint = _fingerprint(replay_path)
    replay_fingerprint["tick_rate"] = int(replay.header.tick_rate)
    replay_fingerprint["seed"] = int(replay.header.seed)
    replay_fingerprint["mode_id"] = int(replay.header.game_mode_id)
    replay_fingerprint["quest_level"] = str(replay.header.quest_level)

    meta = TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": "python",
            "impl_version": "",
            "platform": "",
            "arch": "",
        },
        source=replay_fingerprint,
        channels=sorted(str(channel) for channel in channels_seen),
        channel_versions={str(channel): 1 for channel in sorted(channels_seen)},
        tick_range={
            "start_tick": int(tick_start),
            "end_tick": int(tick_end),
            "tick_count": int(len(tick_rows)),
        },
        config={
            "profile": str(profile),
            "strict_events": bool(strict_events),
            "max_ticks": (None if max_ticks is None else int(max_ticks)),
        },
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, int(chunk_ticks)),
    )
