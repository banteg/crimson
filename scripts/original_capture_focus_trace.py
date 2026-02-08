#!/usr/bin/env python3
from __future__ import annotations

import argparse
import inspect
import json
import math
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from grim.geom import Vec2

import crimson.projectiles as projectiles_mod
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput
from crimson.replay.original_capture import (
    ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND,
    build_original_capture_dt_frame_overrides,
    convert_original_capture_to_replay,
    load_original_capture_sidecar,
    original_capture_bootstrap_payload_from_event_payload,
)
from crimson.replay.types import UnknownEvent, unpack_input_flags, unpack_packed_player_input
from crimson.sim.runners.common import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.runners.survival import _apply_tick_events, _decode_digital_move_keys, _resolve_dt_frame
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
    rng_alignment: RngAlignmentSummary


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
    missing_native_tail_preview: list[RngAlignmentTailRow]


def _read_capture_tick(path: Path, tick: int) -> dict[str, Any] | None:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("event") != "tick":
                continue
            if int(obj.get("tick_index", -1)) != int(tick):
                continue
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
        if isinstance(event, UnknownEvent) and str(event.kind) == ORIGINAL_CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
            payload = original_capture_bootstrap_payload_from_event_payload(list(event.payload))
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
        int(row.get("index")): row for row in capture_creatures if isinstance(row, dict) and row.get("index") is not None
    }
    rows: list[dict[str, Any]] = []
    for idx, cap_row in cap_by_idx.items():
        if not (0 <= int(idx) < len(world.creatures.entries)):
            continue
        creature = world.creatures.entries[int(idx)]
        cap_pos = cap_row.get("pos") if isinstance(cap_row.get("pos"), dict) else {}
        cap_x = float(cap_pos.get("x", 0.0))
        cap_y = float(cap_pos.get("y", 0.0))
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
        int(row.get("index")): row for row in capture_projectiles if isinstance(row, dict) and row.get("index") is not None
    }
    rows: list[dict[str, Any]] = []
    for idx, cap_row in cap_by_idx.items():
        if not (0 <= int(idx) < len(world.state.projectiles.entries)):
            continue
        proj = world.state.projectiles.entries[int(idx)]
        cap_pos = cap_row.get("pos") if isinstance(cap_row.get("pos"), dict) else {}
        cap_x = float(cap_pos.get("x", 0.0))
        cap_y = float(cap_pos.get("y", 0.0))
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
        int(row.get("index")): row for row in capture_creatures if isinstance(row, dict) and row.get("index") is not None
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
                "pos": {"x": float(pos.get("x", 0.0)), "y": float(pos.get("y", 0.0))},
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
        int(row.get("index")): row for row in capture_projectiles if isinstance(row, dict) and row.get("index") is not None
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
                "pos": {"x": float(pos.get("x", 0.0)), "y": float(pos.get("y", 0.0))},
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
        missing_native_tail_preview=tail_preview,
    )


def trace_focus_tick(
    *,
    capture_path: Path,
    tick: int,
    near_miss_threshold: float,
    inter_tick_rand_draws: int,
) -> FocusTraceReport:
    capture = load_original_capture_sidecar(capture_path)
    replay = convert_original_capture_to_replay(capture)
    mode = int(replay.header.game_mode_id)
    if mode != int(GameMode.SURVIVAL):
        raise ValueError(f"focus trace currently supports survival mode only (got mode={mode})")

    raw_tick = _read_capture_tick(capture_path, int(tick))
    if raw_tick is None:
        raise ValueError(f"capture tick {tick} not found in {capture_path}")
    samples = raw_tick.get("samples") if isinstance(raw_tick.get("samples"), dict) else {}
    capture_creatures = samples.get("creatures") if isinstance(samples.get("creatures"), list) else []
    capture_projectiles = samples.get("projectiles") if isinstance(samples.get("projectiles"), list) else []
    capture_rng = raw_tick.get("rng") if isinstance(raw_tick.get("rng"), dict) else {}
    capture_rng_head = capture_rng.get("head") if isinstance(capture_rng.get("head"), list) else []
    capture_rng_calls = int(capture_rng.get("calls", len(capture_rng_head)))

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
    dt_frame_overrides = build_original_capture_dt_frame_overrides(capture, tick_rate=int(replay.header.tick_rate))
    default_dt_frame = 1.0 / float(int(replay.header.tick_rate))

    rng_callsites: Counter[str] = Counter()
    rng_head: list[str] = []
    rng_values: list[int] = []
    rng_values_callsites: list[str] = []
    collision_hits: list[CollisionRow] = []
    near_misses: list[CollisionRow] = []
    pre_projectiles: list[dict[str, Any]] = []
    post_projectiles: list[dict[str, Any]] = []
    focus_hits = 0
    focus_deaths = 0
    focus_sfx = 0

    root = Path.cwd().resolve()
    orig_rand = world.state.rng.rand
    orig_within = projectiles_mod._within_native_find_radius

    try:
        for tick_index in range(int(tick) + 1):
            dt_tick = _resolve_dt_frame(
                tick_index=int(tick_index),
                default_dt_frame=float(default_dt_frame),
                dt_frame_overrides=dt_frame_overrides,
            )
            _apply_tick_events(
                events_by_tick.get(int(tick_index), []),
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
                    frame = inspect.currentframe().f_back
                    proj_index: int | None = None
                    proj_type: int | None = None
                    proj_life: float | None = None
                    step: int | None = None
                    creature_idx: int | None = None
                    if frame is not None:
                        try:
                            step = int(frame.f_locals.get("step")) if "step" in frame.f_locals else None
                        except Exception:
                            step = None
                        try:
                            creature_idx = int(frame.f_locals.get("idx")) if "idx" in frame.f_locals else None
                        except Exception:
                            creature_idx = None
                        try:
                            proj_index = int(frame.f_locals.get("proj_index")) if "proj_index" in frame.f_locals else None
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

                world.state.rng.rand = traced_rand  # type: ignore[assignment]
                projectiles_mod._within_native_find_radius = traced_within_native_find_radius  # type: ignore[assignment]

            tick_result = session.step_tick(
                dt_frame=float(dt_tick),
                inputs=player_inputs,
                trace_rng=False,
            )

            if int(tick_index) == int(tick):
                post_projectiles = _projectile_snapshot(world)
                focus_hits = int(len(tick_result.step.events.hits))
                focus_deaths = int(len(tick_result.step.events.deaths))
                focus_sfx = int(len(tick_result.step.events.sfx))
                world.state.rng.rand = orig_rand  # type: ignore[assignment]
                projectiles_mod._within_native_find_radius = orig_within  # type: ignore[assignment]

            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                world.state.rng.rand()
    finally:
        world.state.rng.rand = orig_rand  # type: ignore[assignment]
        projectiles_mod._within_native_find_radius = orig_within  # type: ignore[assignment]

    near_misses.sort(key=lambda row: float(row.margin))
    collision_hits.sort(key=lambda row: (int(row.proj_index or -1), int(row.step or -1), int(row.creature_idx or -1)))

    creature_diffs_top = _summarize_creature_diffs(capture_creatures, world)
    projectile_diffs_top = _summarize_projectile_diffs(capture_projectiles, world)
    creature_capture_only, creature_rewrite_only = _collect_creature_presence_diffs(capture_creatures, world)
    projectile_capture_only, projectile_rewrite_only = _collect_projectile_presence_diffs(capture_projectiles, world)
    rng_alignment = _summarize_rng_alignment(
        capture_rng_head=[row for row in capture_rng_head if isinstance(row, dict)],
        capture_rng_calls=int(capture_rng_calls),
        rewrite_rng_values=rng_values,
        rewrite_rng_callsites=rng_values_callsites,
    )

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
        capture_projectiles=list(capture_projectiles),
        capture_creatures=list(capture_creatures),
        creature_diffs_top=creature_diffs_top,
        creature_capture_only=creature_capture_only,
        creature_rewrite_only=creature_rewrite_only,
        projectile_diffs_top=projectile_diffs_top,
        projectile_capture_only=projectile_capture_only,
        projectile_rewrite_only=projectile_rewrite_only,
        rng_alignment=rng_alignment,
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


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace a single original-capture tick with rewrite RNG callsites and collision near-miss diagnostics.",
    )
    parser.add_argument("capture", type=Path, help="raw gameplay capture (.jsonl/.jsonl.gz)")
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
    parser.add_argument("--json-out", type=Path, help="optional JSON output path")
    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

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

    if args.json_out is not None:
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
            "rng_alignment": asdict(report.rng_alignment),
        }
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\njson_report={out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
