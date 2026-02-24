#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from crimson.bonuses import BonusId
from crimson.game_modes import GameMode
from crimson.original.capture import CAPTURE_BOOTSTRAP_EVENT_KIND
from crimson.replay import UnknownEvent, apply_replay_bootstrap, unpack_tick_inputs
from crimson.replay.codec import load_replay_file
from crimson.sim.driver.replay_events import apply_replay_tick_events, partition_tick_events
from crimson.sim.driver.replay_timing import (
    resolve_dt_frame,
    resolve_dt_frame_ms_i32,
    should_apply_world_dt_steps_for_replay,
)
from crimson.sim.driver.setup import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.sessions import DeterministicSessionTick, SurvivalDeterministicSession
from crimson.sim.world_state import WorldState


def _round4(value: float) -> float:
    return round(float(value) * 10_000.0) / 10_000.0


def _bonus_timer_ms(value: float) -> int:
    return max(0, int(round(float(value) * 1000.0)))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _get_nested(obj: dict[str, Any], path: str) -> Any:
    current: Any = obj
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                idx = int(part)
            except ValueError:
                return None
            if idx < 0 or idx >= len(current):
                return None
            current = current[idx]
            continue
        return None
    return current


def _scalar_equal(a: Any, b: Any, *, path: str, strict: bool = False) -> bool:
    if path.endswith("elapsed_ms") or path == "elapsed_ms":
        try:
            return abs(int(a) - int(b)) <= 1
        except (TypeError, ValueError):
            return False
    if path.startswith("bonus_timers_raw."):
        try:
            return abs(float(a) - float(b)) <= (1e-9 if strict else 5e-7)
        except (TypeError, ValueError):
            return False
    if isinstance(a, float) or isinstance(b, float):
        try:
            tol = 1e-6 if strict else 2e-2
            return abs(float(a) - float(b)) <= tol
        except (TypeError, ValueError):
            return False
    return a == b


def _first_nested_mismatch(
    a: Any,
    b: Any,
    path: str,
    *,
    strict: bool = False,
) -> tuple[str, Any, Any] | None:
    if isinstance(a, dict) or isinstance(b, dict):
        if not isinstance(a, dict) or not isinstance(b, dict):
            return path, a, b
        a_keys = sorted(a.keys())
        b_keys = sorted(b.keys())
        if a_keys != b_keys:
            return f"{path}.__keys__", a_keys, b_keys
        for key in a_keys:
            next_path = f"{path}.{key}" if path else str(key)
            mismatch = _first_nested_mismatch(a[key], b[key], next_path, strict=strict)
            if mismatch is not None:
                return mismatch
        return None

    if isinstance(a, list) or isinstance(b, list):
        if not isinstance(a, list) or not isinstance(b, list):
            return path, a, b
        if len(a) != len(b):
            return f"{path}.__len__", len(a), len(b)
        for idx, (left, right) in enumerate(zip(a, b, strict=False)):
            next_path = f"{path}.{idx}" if path else str(idx)
            mismatch = _first_nested_mismatch(left, right, next_path, strict=strict)
            if mismatch is not None:
                return mismatch
        return None

    if _scalar_equal(a, b, path=path, strict=strict):
        return None
    return path, a, b


def _python_trace_row(
    tick_index: int,
    *,
    world: WorldState,
    tick: DeterministicSessionTick,
    game_tune_started: bool,
) -> dict[str, Any]:
    state = world.state
    player0 = world.players[0] if world.players else None

    active_projectiles: list[tuple[int, Any]] = [
        (idx, proj) for idx, proj in enumerate(state.projectiles.entries) if bool(proj.active)
    ]
    projectiles_head = [
        {
            "type_id": int(proj.type_id),
            "angle": _round4(float(proj.angle)),
            "speed_scale": _round4(float(proj.speed_scale)),
            "life_timer": _round4(float(proj.life_timer)),
            "damage_pool": _round4(float(proj.damage_pool)),
            "pos": {
                "x": _round4(float(proj.pos.x)),
                "y": _round4(float(proj.pos.y)),
            },
        }
        for _, proj in active_projectiles[:8]
    ]
    projectile_slots_head = [
        {
            "index": int(idx),
            "type_id": int(proj.type_id),
            "owner_id": int(proj.owner_id),
            "angle": _round4(float(proj.angle)),
            "speed_scale": _round4(float(proj.speed_scale)),
            "life_timer": _round4(float(proj.life_timer)),
            "damage_pool": _round4(float(proj.damage_pool)),
            "pos": {
                "x": _round4(float(proj.pos.x)),
                "y": _round4(float(proj.pos.y)),
            },
        }
        for idx, proj in active_projectiles[:64]
    ]

    first_projectile = None
    first_projectile_raw = None
    if active_projectiles:
        _, proj = active_projectiles[0]
        first_projectile = {
            "pos": {
                "x": _round4(float(proj.pos.x)),
                "y": _round4(float(proj.pos.y)),
            },
            "type_id": int(proj.type_id),
            "angle": _round4(float(proj.angle)),
            "life_timer": _round4(float(proj.life_timer)),
            "damage_pool": _round4(float(proj.damage_pool)),
        }
        first_projectile_raw = {
            "pos": {
                "x": float(proj.pos.x),
                "y": float(proj.pos.y),
            },
            "type_id": int(proj.type_id),
            "angle": float(proj.angle),
            "life_timer": float(proj.life_timer),
            "damage_pool": float(proj.damage_pool),
        }

    first_projectile_nearest_creature: dict[str, Any] | None = None
    if active_projectiles:
        _, proj = active_projectiles[0]
        best: tuple[float, Any] | None = None
        for creature in world.creatures.entries:
            if not bool(creature.active):
                continue
            dx = float(creature.pos.x) - float(proj.pos.x)
            dy = float(creature.pos.y) - float(proj.pos.y)
            dist_sq = dx * dx + dy * dy
            if best is None or dist_sq < best[0]:
                best = (dist_sq, creature)
        if best is not None:
            dist_sq, creature = best
            first_projectile_nearest_creature = {
                "distance": _round4(dist_sq**0.5),
                "type_id": int(creature.type_id),
                "hp": _round4(float(creature.hp)),
                "hitbox_size": _round4(float(creature.hitbox_size)),
                "pos": {
                    "x": _round4(float(creature.pos.x)),
                    "y": _round4(float(creature.pos.y)),
                },
            }

    first_creature = next((entry for entry in world.creatures.entries if bool(entry.active)), None)
    first_creature_obj: dict[str, Any] | None = None
    creature_slots_head = [
        {
            "index": int(idx),
            "type_id": int(creature.type_id),
            "hp": _round4(float(creature.hp)),
            "hitbox_size": _round4(float(creature.hitbox_size)),
            "heading": _round4(float(creature.heading)),
            "target_heading": _round4(float(creature.target_heading)),
            "ai_mode": int(creature.ai_mode),
            "link_index": int(creature.link_index),
            "flags": int(creature.flags),
            "attack_cooldown": _round4(float(creature.attack_cooldown)),
            "move_speed": _round4(float(creature.move_speed)),
            "move_scale": _round4(float(creature.move_scale)),
            "size": _round4(float(creature.size)),
            "max_health": _round4(float(creature.max_hp)),
            "contact_damage": _round4(float(creature.contact_damage)),
            "vel": {
                "x": _round4(float(creature.vel.x)),
                "y": _round4(float(creature.vel.y)),
            },
            "force_target": int(creature.force_target),
            "target": {
                "x": _round4(float(creature.target.x)),
                "y": _round4(float(creature.target.y)),
            },
            "phase_seed": _round4(float(creature.phase_seed)),
            "target_offset": (
                None
                if creature.target_offset is None
                else {
                    "x": _round4(float(creature.target_offset.x)),
                    "y": _round4(float(creature.target_offset.y)),
                }
            ),
            "pos": {
                "x": _round4(float(creature.pos.x)),
                "y": _round4(float(creature.pos.y)),
            },
        }
        for idx, creature in [
            (idx, entry) for idx, entry in enumerate(world.creatures.entries) if bool(entry.active)
        ][:64]
    ]
    if first_creature is not None:
        first_creature_obj = {
            "pos": {
                "x": _round4(float(first_creature.pos.x)),
                "y": _round4(float(first_creature.pos.y)),
            },
            "type_id": int(first_creature.type_id),
            "hp": _round4(float(first_creature.hp)),
            "hitbox_size": _round4(float(first_creature.hitbox_size)),
            "heading": _round4(float(first_creature.heading)),
            "target_heading": _round4(float(first_creature.target_heading)),
            "ai_mode": int(first_creature.ai_mode),
            "link_index": int(first_creature.link_index),
            "flags": int(first_creature.flags),
            "attack_cooldown": _round4(float(first_creature.attack_cooldown)),
            "move_speed": _round4(float(first_creature.move_speed)),
            "move_scale": _round4(float(first_creature.move_scale)),
            "size": _round4(float(first_creature.size)),
            "max_health": _round4(float(first_creature.max_hp)),
            "contact_damage": _round4(float(first_creature.contact_damage)),
            "vel": {
                "x": _round4(float(first_creature.vel.x)),
                "y": _round4(float(first_creature.vel.y)),
            },
            "force_target": int(first_creature.force_target),
            "target": {
                "x": _round4(float(first_creature.target.x)),
                "y": _round4(float(first_creature.target.y)),
            },
            "phase_seed": _round4(float(first_creature.phase_seed)),
            "target_offset": (
                None
                if first_creature.target_offset is None
                else {
                    "x": _round4(float(first_creature.target_offset.x)),
                    "y": _round4(float(first_creature.target_offset.y)),
                }
            ),
        }

    bonus_entries = [entry for entry in state.bonus_pool.entries if int(entry.bonus_id) != 0]
    bonus_slots_head = [
        {
            "index": int(idx),
            "bonus_id": int(entry.bonus_id),
            "amount": int(entry.amount),
            "picked": bool(entry.picked),
            "time_left": _round4(float(entry.time_left)),
            "time_max": _round4(float(entry.time_max)),
            "pos": {
                "x": _round4(float(entry.pos.x)),
                "y": _round4(float(entry.pos.y)),
            },
        }
        for idx, entry in enumerate(state.bonus_pool.entries)
        if int(entry.bonus_id) != 0
    ]
    first_bonus_obj: dict[str, Any] | None = None
    if bonus_entries:
        first_bonus = bonus_entries[0]
        first_bonus_obj = {
            "bonus_id": int(first_bonus.bonus_id),
            "amount": int(first_bonus.amount),
            "picked": bool(first_bonus.picked),
            "time_left": _round4(float(first_bonus.time_left)),
            "pos": {
                "x": _round4(float(first_bonus.pos.x)),
                "y": _round4(float(first_bonus.pos.y)),
            },
        }

    weapon_shots_fired = []
    if state.weapon_shots_fired:
        weapon_shots_fired = [int(value) for value in state.weapon_shots_fired[0]]
    if len(weapon_shots_fired) < 128:
        weapon_shots_fired.extend([0] * (128 - len(weapon_shots_fired)))

    hit_details = []
    for hit in tick.step.events.hits[:32]:
        hit_details.append(
            {
                "projectile_index": -1,
                "creature_index": -1,
                "type_id": int(hit.type_id),
                "hit_pos": {
                    "x": _round4(float(hit.hit.x)),
                    "y": _round4(float(hit.hit.y)),
                },
                "target_pos": {
                    "x": _round4(float(hit.target.x)),
                    "y": _round4(float(hit.target.y)),
                },
                "target_size": 0.0,
            },
        )

    return {
        "tick_index": int(tick_index),
        "rng_state": int(state.rng.state),
        "elapsed_ms": int(round(float(tick.elapsed_ms))),
        "score_xp": int(player0.experience) if player0 is not None else 0,
        "kills": int(world.creatures.kill_count),
        "creature_count": int(sum(1 for entry in world.creatures.entries if bool(entry.active))),
        "perk_pending": int(state.perk_selection.pending_count),
        "player0": {
            "pos": {
                "x": 0.0 if player0 is None else _round4(float(player0.pos.x)),
                "y": 0.0 if player0 is None else _round4(float(player0.pos.y)),
            },
            "heading": 0.0 if player0 is None else _round4(float(player0.heading)),
            "turn_speed": 0.0 if player0 is None else _round4(float(player0.turn_speed)),
            "aim_heading": 0.0 if player0 is None else _round4(float(player0.aim_heading)),
            "health": 0.0 if player0 is None else _round4(float(player0.health)),
            "weapon_id": 0 if player0 is None else int(player0.weapon_id),
            "ammo": 0.0 if player0 is None else _round4(float(player0.ammo)),
            "experience": 0 if player0 is None else int(player0.experience),
            "level": 0 if player0 is None else int(player0.level),
            "spread_heat": 0.0 if player0 is None else _round4(float(player0.spread_heat)),
            "shot_cooldown": 0.0 if player0 is None else _round4(float(player0.shot_cooldown)),
            "reload_timer": 0.0 if player0 is None else _round4(float(player0.reload_timer)),
        },
        "player0_raw": {
            "pos": {
                "x": 0.0 if player0 is None else float(player0.pos.x),
                "y": 0.0 if player0 is None else float(player0.pos.y),
            },
            "heading": 0.0 if player0 is None else float(player0.heading),
            "turn_speed": 0.0 if player0 is None else float(player0.turn_speed),
            "aim_heading": 0.0 if player0 is None else float(player0.aim_heading),
            "health": 0.0 if player0 is None else float(player0.health),
            "weapon_id": 0 if player0 is None else int(player0.weapon_id),
            "ammo": 0.0 if player0 is None else float(player0.ammo),
            "experience": 0 if player0 is None else int(player0.experience),
            "level": 0 if player0 is None else int(player0.level),
            "spread_heat": 0.0 if player0 is None else float(player0.spread_heat),
            "shot_cooldown": 0.0 if player0 is None else float(player0.shot_cooldown),
            "reload_timer": 0.0 if player0 is None else float(player0.reload_timer),
        },
        "bonus_timers": {
            str(int(BonusId.WEAPON_POWER_UP)): _bonus_timer_ms(float(state.bonuses.weapon_power_up)),
            str(int(BonusId.REFLEX_BOOST)): _bonus_timer_ms(float(state.bonuses.reflex_boost)),
            str(int(BonusId.ENERGIZER)): _bonus_timer_ms(float(state.bonuses.energizer)),
            str(int(BonusId.DOUBLE_EXPERIENCE)): _bonus_timer_ms(float(state.bonuses.double_experience)),
            str(int(BonusId.FREEZE)): _bonus_timer_ms(float(state.bonuses.freeze)),
        },
        "bonus_timers_raw": {
            str(int(BonusId.WEAPON_POWER_UP)): float(state.bonuses.weapon_power_up),
            str(int(BonusId.REFLEX_BOOST)): float(state.bonuses.reflex_boost),
            str(int(BonusId.ENERGIZER)): float(state.bonuses.energizer),
            str(int(BonusId.DOUBLE_EXPERIENCE)): float(state.bonuses.double_experience),
            str(int(BonusId.FREEZE)): float(state.bonuses.freeze),
        },
        "projectile_count": int(len(active_projectiles)),
        "first_projectile": first_projectile,
        "first_projectile_raw": first_projectile_raw,
        "projectiles_head": projectiles_head,
        "projectile_slots_head": projectile_slots_head,
        "first_creature": first_creature_obj,
        "creature_slots_head": creature_slots_head,
        "first_projectile_nearest_creature": first_projectile_nearest_creature,
        "bonus_count": int(len(bonus_entries)),
        "first_bonus": first_bonus_obj,
        "bonus_slots_head": bonus_slots_head,
        "shots_fired": int(state.shots_fired[0]) if state.shots_fired else 0,
        "shots_hit": int(state.shots_hit[0]) if state.shots_hit else 0,
        "weapon_shots_fired": weapon_shots_fired,
        "time_scale_active": bool(state.time_scale_active),
        "game_tune_started": bool(game_tune_started),
        "debug_hit_sfx_draws_tick": int(len(tick.step.events.hit_sfx)),
        "debug_death_sfx_draws_tick": 0,
        "debug_bonus_flow_draws_tick": 0,
        "debug_weapon_pick_draws_tick": 0,
        "debug_projectile_hits_tick": int(len(tick.step.events.hits)),
        "debug_projectile_hits_detail_tick": hit_details,
    }


def _build_python_trace(
    replay_path: Path,
    *,
    max_ticks: int | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    replay = load_replay_file(replay_path)

    tick_rate = int(replay.header.tick_rate)
    if tick_rate <= 0:
        raise SystemExit(f"invalid replay tick_rate: {tick_rate}")

    world_size = float(replay.header.world_size)
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=bool(replay.header.hardcore),
        difficulty_level=int(replay.header.difficulty_level),
        preserve_bugs=bool(replay.header.preserve_bugs),
    )
    reset_players(
        world.players,
        world_size=float(world_size),
        player_count=int(replay.header.player_count),
    )
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    apply_replay_bootstrap(
        replay.header,
        rng=world.state.rng,
        world_size=float(world_size),
        strict=True,
    )

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
        events_by_tick.setdefault(int(event.tick_index), []).append(event)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        game_tune_started=False,
        apply_world_dt_steps=bool(
            should_apply_world_dt_steps_for_replay(
                original_capture_replay=bool(original_capture_replay),
                dt_frame_overrides=None,
                dt_frame_ms_i32_overrides=None,
            ),
        ),
        clear_fx_queues_each_tick=True,
    )

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))
    dt_frame = 1.0 / float(tick_rate)

    rows: list[dict[str, Any]] = []

    for tick_index in range(tick_limit):
        state = world.state
        state.game_mode = int(GameMode.SURVIVAL)
        state.demo_mode_active = False

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=None,
        )

        tick_events = events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )
        apply_replay_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=True,
        )

        tick = session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=unpack_tick_inputs(inputs[tick_index]),
            trace_rng=False,
        )

        if post_step_events:
            apply_replay_tick_events(
                post_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=world,
                game_mode_id=int(GameMode.SURVIVAL),
                strict_events=True,
            )

        rows.append(
            _python_trace_row(
                int(tick_index),
                world=world,
                tick=tick,
                game_tune_started=bool(session.game_tune_started),
            ),
        )

    if tick_limit == len(inputs):
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_limit),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        apply_replay_tick_events(
            events_by_tick.get(int(tick_limit), []),
            tick_index=int(tick_limit),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=True,
        )

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    run_result = {
        "game_mode_id": int(GameMode.SURVIVAL),
        "tick_rate": int(tick_rate),
        "ticks": int(tick_limit),
        "elapsed_ms": int(session.elapsed_ms),
        "score_xp": int(score_xp),
        "creature_kill_count": int(world.creatures.kill_count),
        "most_used_weapon_id": int(most_used_weapon_id),
        "shots_fired": int(shots_fired),
        "shots_hit": int(shots_hit),
        "rng_state": int(world.state.rng.state),
    }
    return rows, run_result


def _find_first_divergence(
    py_rows: list[dict[str, Any]],
    rust_rows: list[dict[str, Any]],
    *,
    strict: bool = False,
) -> tuple[int, str, Any, Any] | None:
    common_len = min(len(py_rows), len(rust_rows))
    compare_fields = [
        "tick_index",
        "rng_state",
        "elapsed_ms",
        "score_xp",
        "kills",
        "creature_count",
        "perk_pending",
        "player0.pos.x",
        "player0.pos.y",
        "player0.heading",
        "player0.turn_speed",
        "player0.aim_heading",
        "player0.health",
        "player0.weapon_id",
        "player0.ammo",
        "player0.experience",
        "player0.level",
        "player0.spread_heat",
        "player0.shot_cooldown",
        "player0.reload_timer",
        "bonus_timers.4",
        "bonus_timers.9",
        "bonus_timers.2",
        "bonus_timers.6",
        "bonus_timers.11",
        "bonus_timers_raw.4",
        "bonus_timers_raw.9",
        "bonus_timers_raw.2",
        "bonus_timers_raw.6",
        "bonus_timers_raw.11",
        "projectile_count",
        "shots_fired",
        "shots_hit",
        "first_projectile",
        "projectiles_head",
        "projectile_slots_head",
        "first_creature",
        "creature_slots_head",
        "bonus_count",
        "first_bonus",
        "bonus_slots_head",
        "weapon_shots_fired",
        "time_scale_active",
        "game_tune_started",
        "debug_projectile_hits_tick",
        "player0_raw.pos.x",
        "player0_raw.pos.y",
        "player0_raw.heading",
        "player0_raw.turn_speed",
        "player0_raw.aim_heading",
        "player0_raw.spread_heat",
        "player0_raw.shot_cooldown",
        "first_projectile_raw",
    ]

    for idx in range(common_len):
        py_row = py_rows[idx]
        rust_row = rust_rows[idx]
        for field in compare_fields:
            expected = _get_nested(py_row, field)
            actual = _get_nested(rust_row, field)
            mismatch = _first_nested_mismatch(expected, actual, field, strict=strict)
            if mismatch is not None:
                _, expected_val, actual_val = mismatch
                return idx, mismatch[0], expected_val, actual_val

    if len(py_rows) != len(rust_rows):
        return common_len, "row_count", len(py_rows), len(rust_rows)

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Python and Rust verifier checkpoints and report the first divergent tick.",
    )
    parser.add_argument("replay", type=Path, help="Replay file (.crd)")
    parser.add_argument("--max-ticks", type=int, default=None, help="Optional tick limit")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Use strict float comparison (1e-6 tolerance) to surface early drift.",
    )
    parser.add_argument(
        "--keep-traces",
        action="store_true",
        help="Keep emitted Python/Rust trace files in the temp directory",
    )
    args = parser.parse_args()

    replay_path = args.replay.expanduser().resolve()
    if not replay_path.is_file():
        raise SystemExit(f"replay file not found: {replay_path}")

    py_rows, py_run_result = _build_python_trace(
        replay_path,
        max_ticks=(int(args.max_ticks) if args.max_ticks is not None else None),
    )

    with TemporaryDirectory(prefix="crimson-rust-diff-") as tmp_dir_raw:
        tmp_dir = Path(tmp_dir_raw)
        rust_trace_path = tmp_dir / "rust.trace.jsonl"
        py_trace_path = tmp_dir / "python.trace.jsonl"
        py_trace_path.write_text(
            "\n".join(json.dumps(row, separators=(",", ":")) for row in py_rows) + "\n",
            encoding="utf-8",
        )

        root = Path(__file__).resolve().parents[2]
        cargo_manifest = root / "crimson-rust" / "Cargo.toml"
        cmd = [
            "cargo",
            "run",
            "--manifest-path",
            str(cargo_manifest),
            "-p",
            "crimson-rust",
            "--",
            "verify",
            str(replay_path),
            "--format",
            "json",
        ]

        env = os.environ.copy()
        env["CRIMSON_RUST_TRACE_JSONL"] = str(rust_trace_path)
        if args.max_ticks is not None:
            env["CRIMSON_RUST_MAX_TICKS"] = str(int(args.max_ticks))
        proc = subprocess.run(
            cmd,
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        if not rust_trace_path.is_file():
            print(proc.stdout)
            print(proc.stderr)
            raise SystemExit("rust trace file not generated")

        rust_rows = _load_jsonl(rust_trace_path)
        if args.max_ticks is not None:
            rust_rows = rust_rows[: int(args.max_ticks)]

        rust_json = None
        for line in reversed(proc.stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    rust_json = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        divergence = _find_first_divergence(py_rows, rust_rows, strict=bool(args.strict))
        if divergence is None:
            print(f"ok: no divergence in {len(py_rows)} compared ticks")
        else:
            idx, field, expected, actual = divergence
            tick = None
            if idx < len(py_rows):
                tick = py_rows[idx].get("tick_index")
            elif idx < len(rust_rows):
                tick = rust_rows[idx].get("tick_index")
            print("mismatch:")
            print(f"  row_index: {idx}")
            print(f"  tick_index: {tick}")
            print(f"  field: {field}")
            print(f"  python: {expected!r}")
            print(f"  rust:   {actual!r}")

        print("python_run_result:")
        print(json.dumps(py_run_result, indent=2, sort_keys=True))

        if rust_json is not None:
            print("rust_run_result:")
            print(json.dumps(rust_json.get("run_result"), indent=2, sort_keys=True))

        if args.keep_traces:
            kept = replay_path.parent / f"{replay_path.name}.diff"
            kept.mkdir(parents=True, exist_ok=True)
            kept_py = kept / "python.trace.jsonl"
            kept_rust = kept / "rust.trace.jsonl"
            kept_py.write_text(py_trace_path.read_text(encoding="utf-8"), encoding="utf-8")
            kept_rust.write_text(rust_trace_path.read_text(encoding="utf-8"), encoding="utf-8")
            print(f"kept traces in: {kept}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
