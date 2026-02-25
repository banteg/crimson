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
        idx = index
        if idx not in self.active_indices:
            self.generation_by_index[idx] = self.generation_by_index.get(idx, 0) + 1
        self._seen_in_tick.add(idx)
        generation = self.generation_by_index.get(idx, 0)
        kind_code = _ENTITY_KIND_CODES[kind] & 0xFF
        uid = (kind_code << 56) | ((generation & 0xFFFFFF) << 32) | (idx & 0xFFFFFFFF)
        return uid, generation


def _fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _require_numeric(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be numeric, got bool")
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    raise TypeError(f"{field} must be numeric, got {type(value).__name__}")


def _require_object_dict(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"{field} must be a mapping")
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
        else:
            raise TypeError(f"{field} contains non-string key")
    return out


def _require_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be int, got bool")
    if isinstance(value, int):
        return value
    raise TypeError(f"{field} must be int, got {type(value).__name__}")


def _state_mark(marks: dict[str, int], key: str) -> int | None:
    value = marks.get(key)
    if value is None:
        return None
    if value < 0:
        return None
    return value


def _infer_rand_calls_between_states(before_state: int, after_state: int, *, max_calls: int) -> int | None:
    before = before_state & _CRT_RAND_MASK
    after = after_state & _CRT_RAND_MASK
    if before == after:
        return 0
    state = before
    for idx in range(1, max(0, max_calls) + 1):
        state = (state * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        if state == after:
            return idx
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
        before_state,
        after_state,
        max_calls=_CRT_RAND_CALL_SEARCH_LIMIT,
    )
    if total_calls is None:
        return []

    limit = min(max(0, total_calls), max(0, max_rows))
    state = before_state & _CRT_RAND_MASK
    rows: list[dict[str, object]] = []
    for call_index in range(limit):
        state_before_u32 = state & _CRT_RAND_MASK
        state_after_u32 = (state_before_u32 * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MASK
        rows.append(
            {
                "tick_call_index": call_index + 1,
                "value_15": (state_after_u32 >> 16) & 0x7FFF,
                "state_before_u32": state_before_u32,
                "state_after_u32": state_after_u32,
                "caller_static": None,
                "branch_id": None,
                "inferred": True,
            },
        )
        state = state_after_u32
    return rows


def _event_heads_from_checkpoint(checkpoint: ReplayCheckpoint) -> list[dict[str, object]]:
    heads: list[dict[str, object]] = [
        {
            "type": "event_summary",
            "hit_count": checkpoint.events.hit_count,
            "pickup_count": checkpoint.events.pickup_count,
            "sfx_count": checkpoint.events.sfx_count,
        },
    ]
    for entry in checkpoint.deaths:
        heads.append(
            {
                "type": "creature_death",
                "creature_index": entry.creature_index,
                "type_id": entry.type_id,
                "reward_value": float(entry.reward_value),
                "xp_awarded": entry.xp_awarded,
                "owner_id": entry.owner_id,
            },
        )
    for sfx_key in checkpoint.events.sfx_head:
        heads.append({"type": "sfx", "key": str(sfx_key)})
    if checkpoint.perk.pending_count > 0 or checkpoint.perk.choices_dirty:
        heads.append(
            {
                "type": "perk_state",
                "pending_count": checkpoint.perk.pending_count,
                "choices_dirty": bool(checkpoint.perk.choices_dirty),
                "choices_count": len(checkpoint.perk.choices),
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
        mapped = _require_object_dict(item, field="entity_samples.creatures[]")
        uid = _require_int(mapped.get("uid"), field="entity_samples.creatures[].uid")
        out[uid] = mapped
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
        prev_row = prev_creatures[uid]
        curr_row = curr_creatures[uid]
        prev_pos = _require_object_dict(prev_row.get("pos"), field="entity_samples.creatures[].pos")
        curr_pos = _require_object_dict(curr_row.get("pos"), field="entity_samples.creatures[].pos")
        px = _require_numeric(prev_pos.get("x"), field="entity_samples.creatures[].pos.x")
        py = _require_numeric(prev_pos.get("y"), field="entity_samples.creatures[].pos.y")
        cx = _require_numeric(curr_pos.get("x"), field="entity_samples.creatures[].pos.x")
        cy = _require_numeric(curr_pos.get("y"), field="entity_samples.creatures[].pos.y")
        dx = float(cx - px)
        dy = float(cy - py)
        rows.append(
            {
                "type": "creature_update_micro_window",
                "uid": uid,
                "index": _require_int(curr_row.get("index"), field="entity_samples.creatures[].index"),
                "before_pos": {"x": float(px), "y": float(py)},
                "after_pos": {"x": float(cx), "y": float(cy)},
                "dx": float(dx),
                "dy": float(dy),
                "before_hp": _require_numeric(prev_row.get("hp"), field="entity_samples.creatures[].hp"),
                "after_hp": _require_numeric(curr_row.get("hp"), field="entity_samples.creatures[].hp"),
                "before_heading": _require_numeric(prev_row.get("heading"), field="entity_samples.creatures[].heading"),
                "after_heading": _require_numeric(curr_row.get("heading"), field="entity_samples.creatures[].heading"),
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
        uid, generation = creature_state.next_uid(kind="creature", index=index)
        creatures.append(
            {
                "uid": uid,
                "generation": generation,
                "pool_kind": "creature",
                "index": index,
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
        uid, generation = projectile_state.next_uid(kind="projectile", index=index)
        projectiles.append(
            {
                "uid": uid,
                "generation": generation,
                "pool_kind": "projectile",
                "index": index,
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
        uid, generation = secondary_state.next_uid(kind="secondary_projectile", index=index)
        secondary_projectiles.append(
            {
                "uid": uid,
                "generation": generation,
                "pool_kind": "secondary_projectile",
                "index": index,
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
        uid, generation = bonus_state.next_uid(kind="bonus", index=index)
        bonuses.append(
            {
                "uid": uid,
                "generation": generation,
                "pool_kind": "bonus",
                "index": index,
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
    tick_count = replay_tick_count if max_ticks is None else min(replay_tick_count, max(0, max_ticks))
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
        entity_samples_by_tick[tick_index] = _entity_samples_for_world(
            world,
            creature_state=creature_state,
            projectile_state=projectile_state,
            secondary_state=secondary_state,
            bonus_state=bonus_state,
        )

    try:
        run_replay(
            replay,
            max_ticks=max_ticks,
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
    for checkpoint in sorted(checkpoints, key=lambda row: row.tick_index):
        tick_index = checkpoint.tick_index
        channels: dict[str, object] = {
            "checkpoint": checkpoint_to_channel(checkpoint),
        }
        if include_rng:
            channels["rng_marks"] = dict(sorted(checkpoint.rng_marks.items()))
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
                tick_index=tick_index,
                elapsed_ms=checkpoint.elapsed_ms,
                dt_ms_i32=None,
                mode_id=replay.header.game_mode_id,
                phase_markers=[],
                channels=channels,
            ),
        )
        if entity_samples is not None:
            previous_entity_samples = entity_samples

    tick_start = min((row.tick_index for row in tick_rows), default=-1)
    tick_end = max((row.tick_index for row in tick_rows), default=-1)
    replay_fingerprint = _fingerprint(replay_path)
    replay_fingerprint["tick_rate"] = replay.header.tick_rate
    replay_fingerprint["seed"] = replay.header.seed
    replay_fingerprint["mode_id"] = replay.header.game_mode_id
    replay_fingerprint["quest_level"] = str(replay.header.quest_level)

    meta = TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": "python",
            "impl_version": "",
            "platform": "",
            "arch": "",
        },
        source=replay_fingerprint,
        channels=sorted(channels_seen),
        channel_versions={channel: 1 for channel in sorted(channels_seen)},
        tick_range={
            "start_tick": tick_start,
            "end_tick": tick_end,
            "tick_count": len(tick_rows),
        },
        config={
            "profile": profile,
            "strict_events": bool(strict_events),
            "max_ticks": max_ticks,
        },
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, chunk_ticks),
    )
