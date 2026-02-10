from __future__ import annotations

import argparse
import inspect
import json
import math
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import msgspec
from grim.geom import Vec2

import crimson.projectiles as projectiles_mod
import crimson.sim.presentation_step as presentation_step_mod
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    build_capture_dt_frame_overrides,
    build_capture_dt_frame_ms_i32_overrides,
    capture_bootstrap_payload_from_event_payload,
    convert_capture_to_replay,
    load_capture,
)
from crimson.replay.types import UnknownEvent, unpack_input_flags, unpack_packed_player_input
from crimson.sim.runners.common import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.runners.survival import (
    _apply_tick_events,
    _decode_digital_move_keys,
    _partition_tick_events,
    _resolve_dt_frame,
)
from crimson.sim.sessions import SurvivalDeterministicSession
from crimson.sim.world_state import WorldState


@dataclass(slots=True)
class CollisionRow:
    proj_index: int | None
    proj_type: int | None
    proj_life: float | None
    step: int | None
    creature_idx: int | None
    margin: float
    dist: float
    radius: float
    threshold: float
    hit: bool


@dataclass(slots=True)
class FocusTraceReport:
    tick: int
    hits: int
    deaths: int
    sfx: int
    rand_calls_total: int
    rng_callsites_top: list[tuple[str, int]]
    rng_callsites_head: list[str]
    collision_hits: list[CollisionRow]
    collision_near_misses: list[CollisionRow]
    pre_projectiles: list[dict[str, Any]]
    post_projectiles: list[dict[str, Any]]
    capture_projectiles: list[dict[str, Any]]
    capture_creatures: list[dict[str, Any]]
    creature_diffs_top: list[dict[str, Any]]
    creature_capture_only: list[dict[str, Any]]
    creature_rewrite_only: list[dict[str, Any]]
    projectile_diffs_top: list[dict[str, Any]]
    projectile_capture_only: list[dict[str, Any]]
    projectile_rewrite_only: list[dict[str, Any]]
    decal_hook_rows: list[DecalHookRow]
    rng_alignment: RngAlignmentSummary
    native_caller_gaps_top: list[NativeCallerGapRow]
    fire_bullets_loop_parity: FireBulletsLoopParity | None


@dataclass(slots=True)
class DecalHookRow:
    hook_index: int
    type_id: int
    handled: bool
    rng_draws: int
    target_x: float
    target_y: float


@dataclass(slots=True)
class RngAlignmentTailRow:
    index: int
    capture_value: int
    capture_caller_static: str
    capture_caller: str
    inferred_rewrite_callsite: str


@dataclass(slots=True)
class RngAlignmentSummary:
    capture_calls: int
    capture_head_len: int
    rewrite_calls: int
    value_prefix_match: int
    first_value_mismatch_index: int | None
    first_value_mismatch_capture: int | None
    first_value_mismatch_rewrite: int | None
    missing_native_tail_count: int
    missing_native_tail_callers_top: list[tuple[str, int]]
    missing_native_tail_inferred_callsites_top: list[tuple[str, int]]
    missing_native_tail_preview: list[RngAlignmentTailRow]
    capture_caller_counts: list[tuple[str, int]]
    rewrite_callsite_counts: list[tuple[str, int]]
    caller_static_to_rewrite_callsite: list[tuple[str, str]]


@dataclass(slots=True)
class NativeCallerGapRow:
    native_caller_static: str
    native_label: str
    capture_count: int
    inferred_rewrite_callsite: str
    rewrite_count: int
    gap: int


@dataclass(slots=True)
class FireBulletsLoopParity:
    capture_iterations: int
    rewrite_iterations: int
    missing_iterations: int
    loop_iterations_per_hit: int
    estimated_missing_hits: float
    capture_midrange_rolls: int
    rewrite_midrange_rolls: int
    capture_farrange_rolls: int
    rewrite_farrange_rolls: int
    capture_pre_freeze_rolls: int
    rewrite_pre_freeze_rolls: int


_NATIVE_CALLER_LABELS: dict[str, str] = {
    "0x0042176f": "projectile_update.fire_bullets_loop_seed",
    "0x00421799": "projectile_update.fire_bullets_midrange_reroll",
    "0x004217c6": "projectile_update.fire_bullets_farrange_reroll",
    "0x0042184c": "projectile_update.fire_bullets_pre_freeze_rand",
    "0x00427760": "fx_queue_add_random.gray_tint_rand",
    "0x0042778e": "fx_queue_add_random.size_rand",
    "0x004277b0": "fx_queue_add_random.rotation_rand",
    "0x0042780b": "fx_queue_add_random.effect_id_rand",
    "0x0042ebc0": "effect_spawn_blood_splatter.rotation_rand",
    "0x0042ebe3": "effect_spawn_blood_splatter.half_size_rand",
    "0x0042ec00": "effect_spawn_blood_splatter.speed_x_rand",
    "0x0042ec1d": "effect_spawn_blood_splatter.speed_y_rand",
    "0x0042ec44": "effect_spawn_blood_splatter.scale_step_rand",
}

_FIRE_BULLETS_SEED_CALLER = "0x0042176f"
_FIRE_BULLETS_MIDRANGE_CALLER = "0x00421799"
_FIRE_BULLETS_FARRANGE_CALLER = "0x004217c6"
_FIRE_BULLETS_PRE_FREEZE_CALLER = "0x0042184c"
_FIRE_BULLETS_LOOP_ITERS_PER_HIT = 6
_JSON_OUT_AUTO = "__AUTO__"
_DEFAULT_JSON_OUT_DIR = Path("artifacts/frida/reports")


def _resolve_json_out_path(value: str | None, *, tick: int) -> Path | None:
    if value is None:
        return None
    if str(value) == _JSON_OUT_AUTO:
        return _DEFAULT_JSON_OUT_DIR / f"focus_trace_tick{int(tick)}_latest.json"
    return Path(value)


def _read_capture_tick(capture: object, tick: int) -> dict[str, Any] | None:
    ticks = getattr(capture, "ticks", None)
    if not isinstance(ticks, list):
        return None
    for row in ticks:
        if int(getattr(row, "tick_index", -1)) != int(tick):
            continue
        obj = msgspec.to_builtins(row)
        if isinstance(obj, dict):
            return obj
    return None


def _projectile_snapshot(world: WorldState) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, proj in enumerate(world.state.projectiles.entries):
        if not bool(proj.active):
            continue
        out.append(
            {
                "index": int(idx),
                "type_id": int(proj.type_id),
                "life_timer": float(proj.life_timer),
                "damage_pool": float(proj.damage_pool),
                "hit_radius": float(proj.hit_radius),
                "base_damage": float(proj.base_damage),
                "owner_id": int(proj.owner_id),
                "pos": {"x": float(proj.pos.x), "y": float(proj.pos.y)},
            }
        )
    return out


def _decode_inputs_for_tick(
    replay: Any,
    tick_index: int,
    *,
    original_capture_replay: bool,
    digital_move_enabled_by_player: set[int],
) -> list[PlayerInput]:
    packed_tick = replay.inputs[int(tick_index)]
    out: list[PlayerInput] = []
    for player_index, packed in enumerate(packed_tick):
        mx, my, ax, ay, flags = unpack_packed_player_input(packed)
        fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
        move_forward_pressed: bool | None = None
        move_backward_pressed: bool | None = None
        turn_left_pressed: bool | None = None
        turn_right_pressed: bool | None = None
        if original_capture_replay and int(player_index) in digital_move_enabled_by_player:
            digital_move = _decode_digital_move_keys(float(mx), float(my))
            if digital_move is not None:
                (
                    move_forward_pressed,
                    move_backward_pressed,
                    turn_left_pressed,
                    turn_right_pressed,
                ) = digital_move
        out.append(
            PlayerInput(
                move=Vec2(float(mx), float(my)),
                aim=Vec2(float(ax), float(ay)),
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
                move_forward_pressed=move_forward_pressed,
                move_backward_pressed=move_backward_pressed,
                turn_left_pressed=turn_left_pressed,
                turn_right_pressed=turn_right_pressed,
            )
        )
    return out


def _load_capture_events(replay: Any) -> tuple[dict[int, list[object]], bool, set[int]]:
    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    digital_move_enabled_by_player: set[int] = set()
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
            payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
            if isinstance(payload, dict):
                enabled_raw = payload.get("digital_move_enabled_by_player")
                if isinstance(enabled_raw, list):
                    for player_index, enabled in enumerate(enabled_raw):
                        if bool(enabled):
                            digital_move_enabled_by_player.add(int(player_index))
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
    return events_by_tick, original_capture_replay, digital_move_enabled_by_player


def _summarize_creature_diffs(capture_creatures: list[dict[str, Any]], world: WorldState) -> list[dict[str, Any]]:
    cap_by_idx: dict[int, dict[str, Any]] = {
        int(row.get("index")): row for row in capture_creatures if isinstance(row, dict) and row.get("index") is not None  # ty:ignore[invalid-argument-type]
    }
    rows: list[dict[str, Any]] = []
    for idx, cap_row in cap_by_idx.items():
        if not (0 <= int(idx) < len(world.creatures.entries)):
            continue
        creature = world.creatures.entries[int(idx)]
        cap_pos = cap_row.get("pos") if isinstance(cap_row.get("pos"), dict) else {}
        cap_x = float(cap_pos.get("x", 0.0))  # ty:ignore[possibly-missing-attribute]
        cap_y = float(cap_pos.get("y", 0.0))  # ty:ignore[possibly-missing-attribute]
        cap_hp = float(cap_row.get("hp", 0.0))
        cap_hitbox = float(cap_row.get("hitbox_size", 0.0))
        rows.append(
            {
                "index": int(idx),
                "hp_delta": float(creature.hp) - cap_hp,
                "hitbox_delta": float(creature.hitbox_size) - cap_hitbox,
                "x_delta": float(creature.pos.x) - cap_x,
                "y_delta": float(creature.pos.y) - cap_y,
                "active_capture": bool(int(cap_row.get("active", 0)) != 0),
                "active_rewrite": bool(creature.active),
            }
        )
    rows.sort(
        key=lambda row: (
            -max(
                abs(float(row["hp_delta"])),
                abs(float(row["hitbox_delta"])),
                abs(float(row["x_delta"])),
                abs(float(row["y_delta"])),
            ),
            int(row["index"]),
        )
    )
    return rows


def _summarize_projectile_diffs(capture_projectiles: list[dict[str, Any]], world: WorldState) -> list[dict[str, Any]]:
    cap_by_idx: dict[int, dict[str, Any]] = {
        int(row.get("index")): row for row in capture_projectiles if isinstance(row, dict) and row.get("index") is not None  # ty:ignore[invalid-argument-type]
    }
    rows: list[dict[str, Any]] = []
    for idx, cap_row in cap_by_idx.items():
        if not (0 <= int(idx) < len(world.state.projectiles.entries)):
            continue
        proj = world.state.projectiles.entries[int(idx)]
        cap_pos = cap_row.get("pos") if isinstance(cap_row.get("pos"), dict) else {}
        cap_x = float(cap_pos.get("x", 0.0))  # ty:ignore[possibly-missing-attribute]
        cap_y = float(cap_pos.get("y", 0.0))  # ty:ignore[possibly-missing-attribute]
        rows.append(
            {
                "index": int(idx),
                "life_delta": float(proj.life_timer) - float(cap_row.get("life_timer", 0.0)),
                "damage_pool_delta": float(proj.damage_pool) - float(cap_row.get("damage_pool", 0.0)),
                "x_delta": float(proj.pos.x) - cap_x,
                "y_delta": float(proj.pos.y) - cap_y,
                "active_capture": bool(int(cap_row.get("active", 0)) != 0),
                "active_rewrite": bool(proj.active),
            }
        )
    rows.sort(
        key=lambda row: (
            -max(
                abs(float(row["life_delta"])),
                abs(float(row["damage_pool_delta"])),
                abs(float(row["x_delta"])),
                abs(float(row["y_delta"])),
            ),
            int(row["index"]),
        )
    )
    return rows


def _collect_creature_presence_diffs(
    capture_creatures: list[dict[str, Any]],
    world: WorldState,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cap_by_idx: dict[int, dict[str, Any]] = {
        int(row.get("index")): row for row in capture_creatures if isinstance(row, dict) and row.get("index") is not None  # ty:ignore[invalid-argument-type]
    }
    cap_indices = {idx for idx, row in cap_by_idx.items() if bool(int(row.get("active", 0)) != 0)}
    rewrite_indices = {idx for idx, creature in enumerate(world.creatures.entries) if bool(creature.active)}

    capture_only: list[dict[str, Any]] = []
    for idx in sorted(cap_indices - rewrite_indices):
        row = cap_by_idx[int(idx)]
        pos = row.get("pos") if isinstance(row.get("pos"), dict) else {}
        capture_only.append(
            {
                "index": int(idx),
                "type_id": int(row.get("type_id", 0)),
                "hp": float(row.get("hp", 0.0)),
                "hitbox_size": float(row.get("hitbox_size", 0.0)),
                "pos": {"x": float(pos.get("x", 0.0)), "y": float(pos.get("y", 0.0))},  # ty:ignore[possibly-missing-attribute]
            }
        )

    rewrite_only: list[dict[str, Any]] = []
    for idx in sorted(rewrite_indices - cap_indices):
        creature = world.creatures.entries[int(idx)]
        rewrite_only.append(
            {
                "index": int(idx),
                "type_id": int(creature.type_id),
                "hp": float(creature.hp),
                "hitbox_size": float(creature.hitbox_size),
                "pos": {"x": float(creature.pos.x), "y": float(creature.pos.y)},
            }
        )

    return capture_only, rewrite_only


def _collect_projectile_presence_diffs(
    capture_projectiles: list[dict[str, Any]],
    world: WorldState,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cap_by_idx: dict[int, dict[str, Any]] = {
        int(row.get("index")): row for row in capture_projectiles if isinstance(row, dict) and row.get("index") is not None  # ty:ignore[invalid-argument-type]
    }
    cap_indices = {idx for idx, row in cap_by_idx.items() if bool(int(row.get("active", 0)) != 0)}
    rewrite_indices = {idx for idx, proj in enumerate(world.state.projectiles.entries) if bool(proj.active)}

    capture_only: list[dict[str, Any]] = []
    for idx in sorted(cap_indices - rewrite_indices):
        row = cap_by_idx[int(idx)]
        pos = row.get("pos") if isinstance(row.get("pos"), dict) else {}
        capture_only.append(
            {
                "index": int(idx),
                "type_id": int(row.get("type_id", 0)),
                "life_timer": float(row.get("life_timer", 0.0)),
                "damage_pool": float(row.get("damage_pool", 0.0)),
                "pos": {"x": float(pos.get("x", 0.0)), "y": float(pos.get("y", 0.0))},  # ty:ignore[possibly-missing-attribute]
            }
        )

    rewrite_only: list[dict[str, Any]] = []
    for idx in sorted(rewrite_indices - cap_indices):
        proj = world.state.projectiles.entries[int(idx)]
        rewrite_only.append(
            {
                "index": int(idx),
                "type_id": int(proj.type_id),
                "life_timer": float(proj.life_timer),
                "damage_pool": float(proj.damage_pool),
                "pos": {"x": float(proj.pos.x), "y": float(proj.pos.y)},
            }
        )

    return capture_only, rewrite_only


def _summarize_rng_alignment(
    *,
    capture_rng_head: list[dict[str, Any]],
    capture_rng_calls: int,
    rewrite_rng_values: list[int],
    rewrite_rng_callsites: list[str],
    tail_preview_limit: int = 24,
) -> RngAlignmentSummary:
    capture_values = [int(row.get("value", 0)) for row in capture_rng_head if isinstance(row, dict)]
    capture_caller_counts = Counter(
        str(row.get("caller_static", "")).strip()
        for row in capture_rng_head
        if isinstance(row, dict) and str(row.get("caller_static", "")).strip()
    )
    rewrite_callsite_counts = Counter(str(callsite) for callsite in rewrite_rng_callsites if str(callsite))
    capture_calls = max(int(capture_rng_calls), len(capture_values))
    rewrite_calls = len(rewrite_rng_values)
    min_len = min(len(capture_values), rewrite_calls)

    prefix = 0
    while prefix < min_len:
        if int(capture_values[prefix]) != int(rewrite_rng_values[prefix]):
            break
        prefix += 1

    mismatch_index: int | None = None
    mismatch_capture: int | None = None
    mismatch_rewrite: int | None = None
    if prefix < min_len:
        mismatch_index = int(prefix)
        mismatch_capture = int(capture_values[prefix])
        mismatch_rewrite = int(rewrite_rng_values[prefix])

    caller_to_rewrite: dict[str, Counter[str]] = {}
    aligned = min(prefix, len(rewrite_rng_callsites), len(capture_rng_head))
    for idx in range(aligned):
        row = capture_rng_head[idx]
        if not isinstance(row, dict):
            continue
        caller_static = str(row.get("caller_static", "")).strip()
        if not caller_static:
            continue
        bucket = caller_to_rewrite.setdefault(caller_static, Counter())
        bucket[str(rewrite_rng_callsites[idx])] += 1

    caller_best: dict[str, str] = {}
    for caller_static, counts in caller_to_rewrite.items():
        top = counts.most_common(1)
        if not top:
            continue
        caller_best[str(caller_static)] = str(top[0][0])

    tail_start = min(rewrite_calls, len(capture_rng_head))
    tail_rows_raw = capture_rng_head[tail_start:]
    tail_callers = Counter(
        str(row.get("caller_static", "")).strip()
        for row in tail_rows_raw
        if isinstance(row, dict) and str(row.get("caller_static", "")).strip()
    )
    tail_inferred_callsites = Counter(
        str(caller_best.get(caller_static, "<unknown>"))
        for row in tail_rows_raw
        if isinstance(row, dict)
        for caller_static in [str(row.get("caller_static", "")).strip()]
        if caller_static
    )
    tail_preview: list[RngAlignmentTailRow] = []
    for offset, row in enumerate(tail_rows_raw[: max(0, int(tail_preview_limit))]):
        if not isinstance(row, dict):
            continue
        caller_static = str(row.get("caller_static", "")).strip()
        tail_preview.append(
            RngAlignmentTailRow(
                index=int(tail_start + offset),
                capture_value=int(row.get("value", 0)),
                capture_caller_static=caller_static,
                capture_caller=str(row.get("caller", "")).strip(),
                inferred_rewrite_callsite=str(caller_best.get(caller_static, "")),
            )
        )

    missing_native_tail_count = max(0, int(capture_calls) - int(rewrite_calls))
    return RngAlignmentSummary(
        capture_calls=int(capture_calls),
        capture_head_len=int(len(capture_values)),
        rewrite_calls=int(rewrite_calls),
        value_prefix_match=int(prefix),
        first_value_mismatch_index=mismatch_index,
        first_value_mismatch_capture=mismatch_capture,
        first_value_mismatch_rewrite=mismatch_rewrite,
        missing_native_tail_count=int(missing_native_tail_count),
        missing_native_tail_callers_top=[(str(key), int(count)) for key, count in tail_callers.most_common(12)],
        missing_native_tail_inferred_callsites_top=[
            (str(key), int(count)) for key, count in tail_inferred_callsites.most_common(12)
        ],
        missing_native_tail_preview=tail_preview,
        capture_caller_counts=[(str(key), int(count)) for key, count in capture_caller_counts.most_common()],
        rewrite_callsite_counts=[(str(key), int(count)) for key, count in rewrite_callsite_counts.most_common()],
        caller_static_to_rewrite_callsite=sorted(
            ((str(caller_static), str(rewrite_callsite)) for caller_static, rewrite_callsite in caller_best.items()),
            key=lambda item: item[0],
        ),
    )


def _build_native_caller_gaps(
    rng_alignment: RngAlignmentSummary,
    *,
    limit: int = 20,
) -> list[NativeCallerGapRow]:
    caller_map = {
        str(caller_static): str(rewrite_callsite)
        for caller_static, rewrite_callsite in rng_alignment.caller_static_to_rewrite_callsite
    }
    rewrite_counts = Counter(
        {
            str(callsite): int(count)
            for callsite, count in rng_alignment.rewrite_callsite_counts
            if str(callsite)
        }
    )
    rows: list[NativeCallerGapRow] = []
    for caller_static, capture_count in rng_alignment.capture_caller_counts:
        native_caller_static = str(caller_static)
        if not native_caller_static:
            continue
        inferred_rewrite_callsite = str(caller_map.get(native_caller_static, ""))
        rewrite_count = int(rewrite_counts.get(inferred_rewrite_callsite, 0)) if inferred_rewrite_callsite else 0
        gap = int(capture_count) - int(rewrite_count)
        if gap <= 0:
            continue
        rows.append(
            NativeCallerGapRow(
                native_caller_static=native_caller_static,
                native_label=str(_NATIVE_CALLER_LABELS.get(native_caller_static, "")),
                capture_count=int(capture_count),
                inferred_rewrite_callsite=inferred_rewrite_callsite,
                rewrite_count=int(rewrite_count),
                gap=int(gap),
            )
        )
    rows.sort(
        key=lambda row: (
            -int(row.gap),
            -int(row.capture_count),
            str(row.native_caller_static),
        )
    )
    return rows[: max(0, int(limit))]


def _build_fire_bullets_loop_parity(rng_alignment: RngAlignmentSummary) -> FireBulletsLoopParity | None:
    caller_map = {
        str(caller_static): str(rewrite_callsite)
        for caller_static, rewrite_callsite in rng_alignment.caller_static_to_rewrite_callsite
    }
    capture_counts = Counter(
        {
            str(caller_static): int(count)
            for caller_static, count in rng_alignment.capture_caller_counts
            if str(caller_static)
        }
    )
    rewrite_counts = Counter(
        {
            str(callsite): int(count)
            for callsite, count in rng_alignment.rewrite_callsite_counts
            if str(callsite)
        }
    )

    seed_callsite = str(caller_map.get(_FIRE_BULLETS_SEED_CALLER, ""))
    seed_capture = int(capture_counts.get(_FIRE_BULLETS_SEED_CALLER, 0))
    seed_rewrite = int(rewrite_counts.get(seed_callsite, 0)) if seed_callsite else 0

    pre_freeze_callsite = str(caller_map.get(_FIRE_BULLETS_PRE_FREEZE_CALLER, ""))
    pre_freeze_capture = int(capture_counts.get(_FIRE_BULLETS_PRE_FREEZE_CALLER, 0))
    pre_freeze_rewrite = int(rewrite_counts.get(pre_freeze_callsite, 0)) if pre_freeze_callsite else 0

    midrange_callsite = str(caller_map.get(_FIRE_BULLETS_MIDRANGE_CALLER, ""))
    midrange_capture = int(capture_counts.get(_FIRE_BULLETS_MIDRANGE_CALLER, 0))
    midrange_rewrite = int(rewrite_counts.get(midrange_callsite, 0)) if midrange_callsite else 0

    farrange_callsite = str(caller_map.get(_FIRE_BULLETS_FARRANGE_CALLER, ""))
    farrange_capture = int(capture_counts.get(_FIRE_BULLETS_FARRANGE_CALLER, 0))
    farrange_rewrite = int(rewrite_counts.get(farrange_callsite, 0)) if farrange_callsite else 0

    if (
        seed_capture <= 0
        and seed_rewrite <= 0
        and pre_freeze_capture <= 0
        and pre_freeze_rewrite <= 0
        and midrange_capture <= 0
        and midrange_rewrite <= 0
        and farrange_capture <= 0
        and farrange_rewrite <= 0
    ):
        return None

    missing_iterations = max(0, int(seed_capture) - int(seed_rewrite))
    estimated_missing_hits = float(missing_iterations) / float(_FIRE_BULLETS_LOOP_ITERS_PER_HIT)
    return FireBulletsLoopParity(
        capture_iterations=int(seed_capture),
        rewrite_iterations=int(seed_rewrite),
        missing_iterations=int(missing_iterations),
        loop_iterations_per_hit=int(_FIRE_BULLETS_LOOP_ITERS_PER_HIT),
        estimated_missing_hits=float(estimated_missing_hits),
        capture_midrange_rolls=int(midrange_capture),
        rewrite_midrange_rolls=int(midrange_rewrite),
        capture_farrange_rolls=int(farrange_capture),
        rewrite_farrange_rolls=int(farrange_rewrite),
        capture_pre_freeze_rolls=int(pre_freeze_capture),
        rewrite_pre_freeze_rolls=int(pre_freeze_rewrite),
    )


def trace_focus_tick(
    *,
    capture_path: Path,
    tick: int,
    near_miss_threshold: float,
    inter_tick_rand_draws: int,
) -> FocusTraceReport:
    capture = load_capture(capture_path)
    replay = convert_capture_to_replay(capture)
    mode = int(replay.header.game_mode_id)
    if mode != int(GameMode.SURVIVAL):
        raise ValueError(f"focus trace currently supports survival mode only (got mode={mode})")

    raw_tick = _read_capture_tick(capture, int(tick))
    if raw_tick is None:
        raise ValueError(f"capture tick {tick} not found in {capture_path}")
    samples = raw_tick.get("samples") if isinstance(raw_tick.get("samples"), dict) else {}
    capture_creatures = samples.get("creatures") if isinstance(samples.get("creatures"), list) else []  # ty:ignore[possibly-missing-attribute]
    capture_projectiles = samples.get("projectiles") if isinstance(samples.get("projectiles"), list) else []  # ty:ignore[possibly-missing-attribute]
    capture_rng = raw_tick.get("rng") if isinstance(raw_tick.get("rng"), dict) else {}
    capture_rng_head = capture_rng.get("head") if isinstance(capture_rng.get("head"), list) else []  # ty:ignore[possibly-missing-attribute]
    capture_rng_calls = int(capture_rng.get("calls", len(capture_rng_head)))  # ty:ignore[invalid-argument-type, possibly-missing-attribute]

    world_size = float(replay.header.world_size)
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=bool(replay.header.hardcore),
        difficulty_level=int(replay.header.difficulty_level),
        preserve_bugs=bool(replay.header.preserve_bugs),
    )
    reset_players(world.players, world_size=world_size, player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    world.state.rng.srand(int(replay.header.seed))

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=world_size,
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
    )

    events_by_tick, original_capture_replay, digital_move_enabled_by_player = _load_capture_events(replay)
    dt_frame_overrides = build_capture_dt_frame_overrides(capture, tick_rate=int(replay.header.tick_rate))
    dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
    default_dt_frame = 1.0 / float(int(replay.header.tick_rate))
    outside_draws_by_tick = {
        int(item.tick_index): int(item.rng.outside_before_calls)
        for item in capture.ticks
        if int(item.rng.outside_before_calls) >= 0
    }
    if outside_draws_by_tick:
        first_tick_index = min(outside_draws_by_tick)
        # The inferred replay seed already matches the first sampled capture tick.
        outside_draws_by_tick[int(first_tick_index)] = 0
    use_outside_draws = bool(outside_draws_by_tick)

    rng_callsites: Counter[str] = Counter()
    rng_head: list[str] = []
    rng_values: list[int] = []
    rng_values_callsites: list[str] = []
    collision_hits: list[CollisionRow] = []
    near_misses: list[CollisionRow] = []
    decal_hook_rows: list[DecalHookRow] = []
    pre_projectiles: list[dict[str, Any]] = []
    post_projectiles: list[dict[str, Any]] = []
    focus_hits = 0
    focus_deaths = 0
    focus_sfx = 0

    root = Path.cwd().resolve()
    orig_rand = world.state.rng.rand
    orig_particles_rand = world.state.particles._rand
    orig_sprite_effects_rand = world.state.sprite_effects._rand
    orig_within = projectiles_mod._within_native_find_radius
    orig_run_projectile_decal_hooks = presentation_step_mod.run_projectile_decal_hooks

    try:
        for tick_index in range(int(tick) + 1):
            world.state.game_mode = int(GameMode.SURVIVAL)
            world.state.demo_mode_active = False
            if use_outside_draws:
                draws = outside_draws_by_tick.get(int(tick_index))
                if draws is None:
                    draws = int(inter_tick_rand_draws)
                for _ in range(max(0, int(draws))):
                    world.state.rng.rand()
            dt_tick = _resolve_dt_frame(
                tick_index=int(tick_index),
                default_dt_frame=float(default_dt_frame),
                dt_frame_overrides=dt_frame_overrides,
            )
            dt_tick_ms_i32 = dt_frame_ms_i32_overrides.get(int(tick_index))
            tick_events = events_by_tick.get(int(tick_index), [])
            pre_step_events, post_step_events = _partition_tick_events(
                tick_events,
                defer_menu_open=bool(original_capture_replay),
            )

            _apply_tick_events(
                pre_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=world,
                strict_events=False,
            )
            player_inputs = _decode_inputs_for_tick(
                replay,
                int(tick_index),
                original_capture_replay=bool(original_capture_replay),
                digital_move_enabled_by_player=digital_move_enabled_by_player,
            )

            if int(tick_index) == int(tick):
                pre_projectiles = _projectile_snapshot(world)

                def traced_rand() -> int:
                    value = int(orig_rand())
                    frame = inspect.currentframe()
                    caller = frame.f_back if frame is not None else None
                    key = "<unknown>"
                    while caller is not None:
                        filename = Path(caller.f_code.co_filename).resolve()
                        try:
                            rel = filename.relative_to(root)
                        except ValueError:
                            rel = filename
                        rel_s = str(rel)
                        if "src/crimson/" in rel_s:
                            key = f"{rel_s}:{caller.f_code.co_name}:{caller.f_lineno}"
                            break
                        caller = caller.f_back
                    rng_callsites[key] += 1
                    if len(rng_head) < 256:
                        rng_head.append(key)
                    rng_values.append(int(value))
                    rng_values_callsites.append(str(key))
                    return value

                def traced_within_native_find_radius(
                    *,
                    origin: Vec2,
                    target: Vec2,
                    radius: float,
                    target_size: float,
                ) -> bool:
                    dx = float(target.x) - float(origin.x)
                    dy = float(target.y) - float(origin.y)
                    dist = math.sqrt(dx * dx + dy * dy)
                    threshold = float(target_size) * 0.14285715 + 3.0
                    margin = dist - float(radius) - threshold
                    hit = bool(margin < 0.0)
                    frame = inspect.currentframe().f_back  # ty:ignore[possibly-missing-attribute]
                    proj_index: int | None = None
                    proj_type: int | None = None
                    proj_life: float | None = None
                    step: int | None = None
                    creature_idx: int | None = None
                    if frame is not None:
                        try:
                            step = int(frame.f_locals.get("step")) if "step" in frame.f_locals else None  # ty:ignore[invalid-argument-type]
                        except Exception:
                            step = None
                        try:
                            creature_idx = int(frame.f_locals.get("idx")) if "idx" in frame.f_locals else None  # ty:ignore[invalid-argument-type]
                        except Exception:
                            creature_idx = None
                        try:
                            proj_index = int(frame.f_locals.get("proj_index")) if "proj_index" in frame.f_locals else None  # ty:ignore[invalid-argument-type]
                        except Exception:
                            proj_index = None
                        proj = frame.f_locals.get("proj")
                        if proj is not None:
                            try:
                                proj_type = int(getattr(proj, "type_id"))
                                proj_life = float(getattr(proj, "life_timer"))
                            except Exception:
                                proj_type = None
                                proj_life = None
                    row = CollisionRow(
                        proj_index=proj_index,
                        proj_type=proj_type,
                        proj_life=proj_life,
                        step=step,
                        creature_idx=creature_idx,
                        margin=float(margin),
                        dist=float(dist),
                        radius=float(radius),
                        threshold=float(threshold),
                        hit=bool(hit),
                    )
                    if bool(hit):
                        collision_hits.append(row)
                    elif 0.0 <= float(margin) <= float(near_miss_threshold):
                        near_misses.append(row)
                    return bool(hit)

                hook_index = 0

                def traced_run_projectile_decal_hooks(ctx: Any) -> bool:
                    nonlocal hook_index
                    before = len(rng_values)
                    handled = bool(orig_run_projectile_decal_hooks(ctx))
                    after = len(rng_values)
                    hit = ctx.hit
                    decal_hook_rows.append(
                        DecalHookRow(
                            hook_index=int(hook_index),
                            type_id=int(hit.type_id),
                            handled=bool(handled),
                            rng_draws=max(0, int(after - before)),
                            target_x=float(hit.target.x),
                            target_y=float(hit.target.y),
                        )
                    )
                    hook_index += 1
                    return bool(handled)

                world.state.rng.rand = traced_rand  # type: ignore[assignment]
                world.state.particles._rand = traced_rand
                world.state.sprite_effects._rand = traced_rand
                projectiles_mod._within_native_find_radius = traced_within_native_find_radius  # type: ignore[assignment]
                presentation_step_mod.run_projectile_decal_hooks = traced_run_projectile_decal_hooks  # type: ignore[assignment]

            tick_result = session.step_tick(
                dt_frame=float(dt_tick),
                dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
                inputs=player_inputs,
                trace_rng=False,
            )

            if int(tick_index) == int(tick):
                post_projectiles = _projectile_snapshot(world)
                focus_hits = int(len(tick_result.step.events.hits))
                focus_deaths = int(len(tick_result.step.events.deaths))
                focus_sfx = int(len(tick_result.step.events.sfx))

            if post_step_events:
                _apply_tick_events(
                    post_step_events,
                    tick_index=int(tick_index),
                    dt_frame=float(dt_tick),
                    world=world,
                    strict_events=False,
                )

            if int(tick_index) == int(tick):
                world.state.rng.rand = orig_rand  # type: ignore[assignment]
                world.state.particles._rand = orig_particles_rand
                world.state.sprite_effects._rand = orig_sprite_effects_rand
                projectiles_mod._within_native_find_radius = orig_within
                presentation_step_mod.run_projectile_decal_hooks = orig_run_projectile_decal_hooks

            if not use_outside_draws:
                draws = max(0, int(inter_tick_rand_draws))
                for _ in range(draws):
                    world.state.rng.rand()
    finally:
        world.state.rng.rand = orig_rand  # type: ignore[assignment]
        world.state.particles._rand = orig_particles_rand
        world.state.sprite_effects._rand = orig_sprite_effects_rand
        projectiles_mod._within_native_find_radius = orig_within
        presentation_step_mod.run_projectile_decal_hooks = orig_run_projectile_decal_hooks

    near_misses.sort(key=lambda row: float(row.margin))
    collision_hits.sort(key=lambda row: (int(row.proj_index or -1), int(row.step or -1), int(row.creature_idx or -1)))

    creature_diffs_top = _summarize_creature_diffs(capture_creatures, world)  # ty:ignore[invalid-argument-type]
    projectile_diffs_top = _summarize_projectile_diffs(capture_projectiles, world)  # ty:ignore[invalid-argument-type]
    creature_capture_only, creature_rewrite_only = _collect_creature_presence_diffs(capture_creatures, world)  # ty:ignore[invalid-argument-type]
    projectile_capture_only, projectile_rewrite_only = _collect_projectile_presence_diffs(capture_projectiles, world)  # ty:ignore[invalid-argument-type]
    rng_alignment = _summarize_rng_alignment(
        capture_rng_head=[row for row in capture_rng_head if isinstance(row, dict)],  # ty:ignore[not-iterable]
        capture_rng_calls=int(capture_rng_calls),
        rewrite_rng_values=rng_values,
        rewrite_rng_callsites=rng_values_callsites,
    )
    native_caller_gaps_top = _build_native_caller_gaps(rng_alignment)
    fire_bullets_loop_parity = _build_fire_bullets_loop_parity(rng_alignment)

    return FocusTraceReport(
        tick=int(tick),
        hits=int(focus_hits),
        deaths=int(focus_deaths),
        sfx=int(focus_sfx),
        rand_calls_total=int(sum(rng_callsites.values())),
        rng_callsites_top=list(rng_callsites.most_common(64)),
        rng_callsites_head=list(rng_head),
        collision_hits=collision_hits,
        collision_near_misses=near_misses,
        pre_projectiles=pre_projectiles,
        post_projectiles=post_projectiles,
        capture_projectiles=list(capture_projectiles),  # ty:ignore[invalid-argument-type]
        capture_creatures=list(capture_creatures),  # ty:ignore[invalid-argument-type]
        creature_diffs_top=creature_diffs_top,
        creature_capture_only=creature_capture_only,
        creature_rewrite_only=creature_rewrite_only,
        projectile_diffs_top=projectile_diffs_top,
        projectile_capture_only=projectile_capture_only,
        projectile_rewrite_only=projectile_rewrite_only,
        decal_hook_rows=decal_hook_rows,
        rng_alignment=rng_alignment,
        native_caller_gaps_top=native_caller_gaps_top,
        fire_bullets_loop_parity=fire_bullets_loop_parity,
    )


def _print_report(report: FocusTraceReport, *, top_rng: int, near_miss_limit: int, diff_limit: int) -> None:
    print(f"tick={int(report.tick)} hits={int(report.hits)} deaths={int(report.deaths)} sfx={int(report.sfx)}")
    print(f"rand_calls_total={int(report.rand_calls_total)}")

    print("\nrng_value_alignment:")
    align = report.rng_alignment
    print(
        "  "
        f"capture_calls={int(align.capture_calls)} capture_head_len={int(align.capture_head_len)} "
        f"rewrite_calls={int(align.rewrite_calls)} prefix_match={int(align.value_prefix_match)}"
    )
    if align.first_value_mismatch_index is not None:
        print(
            "  "
            f"first_value_mismatch_idx={int(align.first_value_mismatch_index)} "
            f"capture={int(align.first_value_mismatch_capture or 0)} "
            f"rewrite={int(align.first_value_mismatch_rewrite or 0)}"
        )
    if int(align.missing_native_tail_count) > 0:
        print(f"  missing_native_tail={int(align.missing_native_tail_count)}")
        if align.missing_native_tail_callers_top:
            print("  missing_native_tail_callers_top:")
            for caller_static, count in align.missing_native_tail_callers_top:
                print(f"    {caller_static}: {int(count)}")
        if align.missing_native_tail_inferred_callsites_top:
            print("  missing_native_tail_inferred_callsites_top:")
            for callsite, count in align.missing_native_tail_inferred_callsites_top:
                print(f"    {callsite}: {int(count)}")
        if align.missing_native_tail_preview:
            print("  missing_native_tail_preview:")
            for row in align.missing_native_tail_preview[: max(1, int(diff_limit))]:
                inferred = str(row.inferred_rewrite_callsite) if str(row.inferred_rewrite_callsite) else "<unknown>"
                print(
                    "    "
                    f"idx={int(row.index)} caller={row.capture_caller_static} value={int(row.capture_value)} "
                    f"inferred={inferred}"
                )
            if len(align.missing_native_tail_preview) > int(diff_limit):
                print(f"    ... {len(align.missing_native_tail_preview) - int(diff_limit)} more")

    if report.native_caller_gaps_top:
        print("\nnative_caller_gaps_top:")
        for row in report.native_caller_gaps_top[: max(1, int(diff_limit))]:
            label = str(row.native_label) if str(row.native_label) else "<unmapped>"
            inferred = str(row.inferred_rewrite_callsite) if str(row.inferred_rewrite_callsite) else "<unknown>"
            print(
                "  "
                f"{row.native_caller_static} ({label}) "
                f"capture={int(row.capture_count)} rewrite={int(row.rewrite_count)} "
                f"gap={int(row.gap)} inferred={inferred}"
            )
        if len(report.native_caller_gaps_top) > int(diff_limit):
            print(f"  ... {len(report.native_caller_gaps_top) - int(diff_limit)} more")

    if report.fire_bullets_loop_parity is not None:
        parity = report.fire_bullets_loop_parity
        print("\nfire_bullets_loop_parity:")
        print(
            "  "
            f"seed_iterations capture={int(parity.capture_iterations)} rewrite={int(parity.rewrite_iterations)} "
            f"missing={int(parity.missing_iterations)}"
        )
        print(
            "  "
            f"estimated_missing_hits={float(parity.estimated_missing_hits):.3f} "
            f"(iters_per_hit={int(parity.loop_iterations_per_hit)})"
        )
        print(
            "  "
            f"midrange_rerolls capture={int(parity.capture_midrange_rolls)} "
            f"rewrite={int(parity.rewrite_midrange_rolls)}"
        )
        print(
            "  "
            f"farrange_rerolls capture={int(parity.capture_farrange_rolls)} "
            f"rewrite={int(parity.rewrite_farrange_rolls)}"
        )
        print(
            "  "
            f"pre_freeze_rolls capture={int(parity.capture_pre_freeze_rolls)} "
            f"rewrite={int(parity.rewrite_pre_freeze_rolls)}"
        )

    print("\nrng_callsites_top:")
    for key, count in report.rng_callsites_top[: max(1, int(top_rng))]:
        print(f"  {int(count):4d} {key}")

    print("\ncollision_hits:")
    for row in report.collision_hits[: max(1, int(near_miss_limit))]:
        print(
            f"  proj={row.proj_index} step={row.step} creature={row.creature_idx} "
            f"margin={row.margin:.6f} dist={row.dist:.6f} threshold={row.threshold:.6f}"
        )
    if len(report.collision_hits) > int(near_miss_limit):
        print(f"  ... {len(report.collision_hits) - int(near_miss_limit)} more")

    print("\ncollision_near_misses:")
    for row in report.collision_near_misses[: max(1, int(near_miss_limit))]:
        print(
            f"  proj={row.proj_index} step={row.step} creature={row.creature_idx} "
            f"margin={row.margin:.6f} dist={row.dist:.6f} threshold={row.threshold:.6f}"
        )
    if len(report.collision_near_misses) > int(near_miss_limit):
        print(f"  ... {len(report.collision_near_misses) - int(near_miss_limit)} more")

    print("\ncreature_diffs_top:")
    for row in report.creature_diffs_top[: max(1, int(diff_limit))]:
        print(
            f"  idx={int(row['index']):3d} hp_delta={float(row['hp_delta']):+.6f} "
            f"hitbox_delta={float(row['hitbox_delta']):+.6f} "
            f"x_delta={float(row['x_delta']):+.6f} y_delta={float(row['y_delta']):+.6f} "
            f"active={bool(row['active_capture'])}/{bool(row['active_rewrite'])}"
        )

    print("\ncreature_presence_diffs:")
    if report.creature_capture_only:
        print("  capture_only_indices:")
        for row in report.creature_capture_only[: max(1, int(diff_limit))]:
            print(
                f"    idx={int(row['index']):3d} type={int(row['type_id'])} "
                f"hp={float(row['hp']):.6f} hitbox={float(row['hitbox_size']):.6f} "
                f"pos=({float(row['pos']['x']):.4f},{float(row['pos']['y']):.4f})"
            )
        if len(report.creature_capture_only) > int(diff_limit):
            print(f"    ... {len(report.creature_capture_only) - int(diff_limit)} more")
    if report.creature_rewrite_only:
        print("  rewrite_only_indices:")
        for row in report.creature_rewrite_only[: max(1, int(diff_limit))]:
            print(
                f"    idx={int(row['index']):3d} type={int(row['type_id'])} "
                f"hp={float(row['hp']):.6f} hitbox={float(row['hitbox_size']):.6f} "
                f"pos=({float(row['pos']['x']):.4f},{float(row['pos']['y']):.4f})"
            )
        if len(report.creature_rewrite_only) > int(diff_limit):
            print(f"    ... {len(report.creature_rewrite_only) - int(diff_limit)} more")
    if not report.creature_capture_only and not report.creature_rewrite_only:
        print("  none")

    print("\nprojectile_diffs_top:")
    for row in report.projectile_diffs_top[: max(1, int(diff_limit))]:
        print(
            f"  idx={int(row['index']):3d} life_delta={float(row['life_delta']):+.6f} "
            f"damage_pool_delta={float(row['damage_pool_delta']):+.6f} "
            f"x_delta={float(row['x_delta']):+.6f} y_delta={float(row['y_delta']):+.6f} "
            f"active={bool(row['active_capture'])}/{bool(row['active_rewrite'])}"
        )

    print("\nprojectile_presence_diffs:")
    if report.projectile_capture_only:
        print("  capture_only_indices:")
        for row in report.projectile_capture_only[: max(1, int(diff_limit))]:
            print(
                f"    idx={int(row['index']):3d} type={int(row['type_id'])} "
                f"life={float(row['life_timer']):.6f} damage_pool={float(row['damage_pool']):.6f} "
                f"pos=({float(row['pos']['x']):.4f},{float(row['pos']['y']):.4f})"
            )
        if len(report.projectile_capture_only) > int(diff_limit):
            print(f"    ... {len(report.projectile_capture_only) - int(diff_limit)} more")
    if report.projectile_rewrite_only:
        print("  rewrite_only_indices:")
        for row in report.projectile_rewrite_only[: max(1, int(diff_limit))]:
            print(
                f"    idx={int(row['index']):3d} type={int(row['type_id'])} "
                f"life={float(row['life_timer']):.6f} damage_pool={float(row['damage_pool']):.6f} "
                f"pos=({float(row['pos']['x']):.4f},{float(row['pos']['y']):.4f})"
            )
        if len(report.projectile_rewrite_only) > int(diff_limit):
            print(f"    ... {len(report.projectile_rewrite_only) - int(diff_limit)} more")
    if not report.projectile_capture_only and not report.projectile_rewrite_only:
        print("  none")

    print("\ndecal_hook_rows:")
    if report.decal_hook_rows:
        for row in report.decal_hook_rows[: max(1, int(diff_limit))]:
            print(
                f"  hook={int(row.hook_index):2d} type={int(row.type_id):2d} handled={int(bool(row.handled))} "
                f"rng_draws={int(row.rng_draws):3d} target=({float(row.target_x):.4f},{float(row.target_y):.4f})"
            )
        if len(report.decal_hook_rows) > int(diff_limit):
            print(f"  ... {len(report.decal_hook_rows) - int(diff_limit)} more")
    else:
        print("  none")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace a single original-capture tick with rewrite RNG callsites and collision near-miss diagnostics.",
    )
    parser.add_argument("capture", type=Path, help="capture file (.json/.json.gz)")
    parser.add_argument("--tick", type=int, required=True, help="tick index to trace")
    parser.add_argument(
        "--near-miss-threshold",
        type=float,
        default=0.35,
        help="include non-hit collision checks with 0 <= margin <= threshold",
    )
    parser.add_argument("--near-miss-limit", type=int, default=24, help="max rows for hit/near-miss print")
    parser.add_argument("--top-rng", type=int, default=24, help="max RNG callsites to print")
    parser.add_argument("--diff-limit", type=int, default=16, help="max sample-diff rows to print")
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="extra rand draws between ticks (native console loop parity)",
    )
    parser.add_argument(
        "--json-out",
        nargs="?",
        default=None,
        const=_JSON_OUT_AUTO,
        help=(
            "optional JSON output path "
            "(default when flag is present: artifacts/frida/reports/focus_trace_tick<TICK>_latest.json)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    json_out_path = _resolve_json_out_path(args.json_out, tick=int(args.tick))

    report = trace_focus_tick(
        capture_path=Path(args.capture),
        tick=int(args.tick),
        near_miss_threshold=max(0.0, float(args.near_miss_threshold)),
        inter_tick_rand_draws=max(0, int(args.inter_tick_rand_draws)),
    )
    _print_report(
        report,
        top_rng=max(1, int(args.top_rng)),
        near_miss_limit=max(1, int(args.near_miss_limit)),
        diff_limit=max(1, int(args.diff_limit)),
    )

    if json_out_path is not None:
        payload = {
            "tick": int(report.tick),
            "hits": int(report.hits),
            "deaths": int(report.deaths),
            "sfx": int(report.sfx),
            "rand_calls_total": int(report.rand_calls_total),
            "rng_callsites_top": [[key, int(count)] for key, count in report.rng_callsites_top],
            "rng_callsites_head": list(report.rng_callsites_head),
            "collision_hits": [asdict(row) for row in report.collision_hits],
            "collision_near_misses": [asdict(row) for row in report.collision_near_misses],
            "pre_projectiles": list(report.pre_projectiles),
            "post_projectiles": list(report.post_projectiles),
            "capture_projectiles": list(report.capture_projectiles),
            "capture_creatures": list(report.capture_creatures),
            "creature_diffs_top": list(report.creature_diffs_top),
            "creature_capture_only": list(report.creature_capture_only),
            "creature_rewrite_only": list(report.creature_rewrite_only),
            "projectile_diffs_top": list(report.projectile_diffs_top),
            "projectile_capture_only": list(report.projectile_capture_only),
            "projectile_rewrite_only": list(report.projectile_rewrite_only),
            "decal_hook_rows": [asdict(row) for row in report.decal_hook_rows],
            "rng_alignment": asdict(report.rng_alignment),
            "native_caller_gaps_top": [asdict(row) for row in report.native_caller_gaps_top],
            "fire_bullets_loop_parity": (
                asdict(report.fire_bullets_loop_parity) if report.fire_bullets_loop_parity is not None else None
            ),
        }
        out_path = json_out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\njson_report={out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
