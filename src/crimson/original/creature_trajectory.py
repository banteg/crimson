from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, cast

from crimson.game_modes import GameMode
from crimson.gameplay import build_gameplay_state
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_dt_frame_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    capture_bootstrap_payload_from_event_payload,
    convert_capture_to_replay,
    load_capture,
)
from crimson.original.schema import CaptureFile
from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import apply_replay_bootstrap
from crimson.replay.types import (
    UnknownEvent,
    unpack_input_flags,
    unpack_input_mode_flags,
    unpack_input_move_key_flags,
    unpack_packed_player_input,
)
from crimson.sim.driver.replay_events import apply_replay_tick_events, partition_tick_events
from crimson.sim.driver.replay_timing import (
    resolve_dt_frame,
    resolve_dt_frame_ms_i32,
    should_apply_world_dt_steps_for_replay,
)
from crimson.sim.driver.setup import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import QuestDeterministicSession, SurvivalDeterministicSession
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2

_JSON_OUT_AUTO = "__AUTO__"
_DEFAULT_JSON_OUT_DIR = Path("artifacts/frida/reports")


@dataclass(slots=True)
class CreatureTrajectoryRow:
    tick: int
    cap_type_id: int
    rw_type_id: int
    cap_flags: int
    rw_flags: int
    cap_active: bool
    rw_active: bool
    cap_target_player: int
    rw_target_player: int
    rw_ai_mode: int
    cap_hp: float
    rw_hp: float
    hp_delta: float
    cap_hitbox: float
    rw_hitbox: float
    hitbox_delta: float
    cap_collision_flag: int
    cap_state_flag: int
    rw_plague_infected: bool
    rw_attack_cooldown: float
    rw_move_scale: float
    cap_heading: float
    cap_target_heading: float
    rw_heading: float
    rw_target_heading: float
    rw_force_target: int
    rw_target_x: float
    rw_target_y: float
    rw_target_dist: float
    rw_orbit_radius: float
    cap_x: float
    cap_y: float
    rw_x: float
    rw_y: float
    dx: float
    dy: float
    drift_mag: float


def _resolve_json_out_path(
    value: str | None,
    *,
    creature_index: int,
    start_tick: int,
    end_tick: int,
) -> Path | None:
    if value is None:
        return None
    if str(value) == _JSON_OUT_AUTO:
        return _DEFAULT_JSON_OUT_DIR / (f"creature{int(creature_index)}_{int(start_tick)}_{int(end_tick)}_latest.json")
    return Path(value)


def _read_capture_creature_samples(
    *,
    capture: CaptureFile,
    creature_index: int,
    start_tick: int,
    end_tick: int,
) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for tick_row in capture.ticks:
        tick = int(tick_row.tick_index)
        if tick < int(start_tick) or tick > int(end_tick):
            continue
        for row in tick_row.samples.creatures:
            if int(row.index) != int(creature_index):
                continue
            out[int(tick)] = {
                "type_id": int(row.type_id),
                "flags": int(row.flags),
                "active": int(row.active),
                "target_player": int(row.target_player),
                "hp": float(row.hp),
                "hitbox_size": float(row.hitbox_size),
                "collision_flag": int(row.collision_flag),
                "state_flag": int(row.state_flag),
                "heading": (0.0 if row.heading is None else float(row.heading)),
                "target_heading": (0.0 if row.target_heading is None else float(row.target_heading)),
                "pos": {"x": float(row.pos.x), "y": float(row.pos.y)},
            }
            break
    return out


def _load_capture_events(
    replay: Any,
) -> tuple[dict[int, list[object]], bool, int | None, bool]:
    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    bootstrap_start_tick: int | None = None
    has_capture_creature_spawn_events = False
    for event in replay.events:
        tick_index = int(event.tick_index)
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
            if bootstrap_start_tick is None or tick_index < int(bootstrap_start_tick):
                bootstrap_start_tick = int(tick_index)
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_CREATURE_SPAWN_EVENT_KIND:
            has_capture_creature_spawn_events = True
        if tick_index not in events_by_tick:
            events_by_tick[tick_index] = []
        events_by_tick[tick_index].append(event)
    return events_by_tick, original_capture_replay, bootstrap_start_tick, has_capture_creature_spawn_events


def _resolve_quest_level(replay: Any) -> str:
    quest_level = str(replay.header.quest_level or "")
    if quest_level:
        return str(quest_level)

    seed = int(replay.header.seed)
    major = seed // 100
    minor = seed % 100
    if 1 <= int(major) <= 5 and 1 <= int(minor) <= 10:
        return f"{major}.{minor}"
    return ""


def _decode_inputs_for_tick(
    *,
    replay: Any,
    tick_index: int,
) -> list[PlayerInput]:
    packed_tick = replay.inputs[int(tick_index)]
    out: list[PlayerInput] = []
    for packed in packed_tick:
        mx, my, ax, ay, flags = unpack_packed_player_input(packed)
        fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
        move_mode, aim_scheme = unpack_input_mode_flags(int(flags))
        move_forward_pressed, move_backward_pressed, turn_left_pressed, turn_right_pressed = (
            unpack_input_move_key_flags(int(flags))
        )
        out.append(
            PlayerInput(
                move=Vec2(float(mx), float(my)),
                aim=Vec2(float(ax), float(ay)),
                move_mode=move_mode,
                aim_scheme=aim_scheme,
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
                move_forward_pressed=move_forward_pressed,
                move_backward_pressed=move_backward_pressed,
                turn_left_pressed=turn_left_pressed,
                turn_right_pressed=turn_right_pressed,
            ),
        )
    return out


def trace_creature_trajectory(
    *,
    capture_path: Path,
    creature_index: int,
    start_tick: int,
    end_tick: int,
    inter_tick_rand_draws: int,
) -> list[CreatureTrajectoryRow]:
    capture = load_capture(capture_path)
    capture_rows = _read_capture_creature_samples(
        capture=capture,
        creature_index=int(creature_index),
        start_tick=int(start_tick),
        end_tick=int(end_tick),
    )
    if not capture_rows:
        return []
    replay = convert_capture_to_replay(capture)
    mode = int(replay.header.game_mode_id)
    if mode not in {int(GameMode.SURVIVAL), int(GameMode.QUESTS)}:
        raise ValueError(
            f"trajectory trace currently supports survival/quests only (got mode={mode})",
        )

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

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session_survival: SurvivalDeterministicSession | None = None
    session_quest: QuestDeterministicSession | None = None

    events_by_tick, original_capture_replay, bootstrap_start_tick, has_capture_creature_spawn_events = (
        _load_capture_events(
            replay,
        )
    )
    dt_frame_overrides = build_capture_dt_frame_overrides(capture, tick_rate=int(replay.header.tick_rate))
    dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
    inter_tick_rand_draws_by_tick = build_capture_inter_tick_rand_draws_overrides(capture)
    default_dt_frame = 1.0 / float(int(replay.header.tick_rate))
    apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=dt_frame_overrides,
        dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
    )

    tick_begin = 0
    pending_capture_state_reset = False
    reset_spawn_entries: tuple[Any, ...] = ()
    quest_start_weapon_id = int(WeaponId.PISTOL)

    if mode == int(GameMode.SURVIVAL):
        apply_replay_bootstrap(
            replay.header,
            rng=world.state.rng,
            world_size=float(world_size),
            strict=True,
        )
        session_survival = SurvivalDeterministicSession(
            world=world,
            world_size=world_size,
            damage_scale_by_type=damage_scale_by_type,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            detail_preset=5,
            fx_toggle=0,
            game_tune_started=False,
            clear_fx_queues_each_tick=True,
            apply_world_dt_steps=bool(apply_world_dt_steps),
        )
    else:
        world.state.rng.srand(int(replay.header.seed))
        quest_level = _resolve_quest_level(replay)
        quest = quest_by_level(quest_level) if quest_level else None
        if quest is None:
            raise ValueError(f"trajectory trace unsupported quest replay: unknown quest_level={quest_level!r}")

        world.state.quest_stage_major, world.state.quest_stage_minor = quest.level_key
        weapon_id = max(1, int(quest.start_weapon_id or 1))
        quest_start_weapon_id = int(weapon_id)
        for player in world.players:
            weapon_assign_player(player, int(weapon_id))

        ctx = QuestContext(
            width=int(world_size),
            height=int(world_size),
            player_count=int(replay.header.player_count),
        )
        spawn_entries = tuple(
            build_quest_spawn_table(
                quest,
                ctx,
                seed=int(replay.header.seed),
                hardcore=bool(replay.header.hardcore),
                full_version=True,
            ),
        )
        capture_spawn_events_authoritative = bool(original_capture_replay) and bool(has_capture_creature_spawn_events)
        session_spawn_entries: tuple[Any, ...] = tuple(spawn_entries)
        if capture_spawn_events_authoritative:
            # Mid-capture quest timelines rely on capture spawn hooks.
            session_spawn_entries = ()
        world.creatures.capture_spawn_events_authoritative = bool(capture_spawn_events_authoritative)
        reset_spawn_entries = tuple(session_spawn_entries)

        session_quest = QuestDeterministicSession(
            world=world,
            world_size=float(world_size),
            damage_scale_by_type=damage_scale_by_type,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            spawn_entries=tuple(session_spawn_entries),
            detail_preset=5,
            fx_toggle=0,
            apply_world_dt_steps=bool(apply_world_dt_steps),
            clear_fx_queues_each_tick=True,
            finalize_post_render_lifecycle_each_tick=False,
        )

        def _apply_capture_state_reset() -> None:
            nonlocal pending_capture_state_reset

            rng_state = int(world.state.rng.state)
            status = world.state.status
            demo_mode_active = bool(world.state.demo_mode_active)
            hardcore = bool(world.state.hardcore)
            preserve_bugs = bool(world.state.preserve_bugs)
            quest_stage_major_state = int(world.state.quest_stage_major)
            quest_stage_minor_state = int(world.state.quest_stage_minor)
            perk_pending = int(world.state.perk_selection.pending_count)
            perk_choices = list(world.state.perk_selection.choices)
            perk_choices_dirty = bool(world.state.perk_selection.choices_dirty)
            man_bomb_interval = float(world.state.perk_intervals.man_bomb)
            fire_cough_interval = float(world.state.perk_intervals.fire_cough)
            hot_tempered_interval = float(world.state.perk_intervals.hot_tempered)

            world.state = build_gameplay_state()
            world.state.rng.srand(int(rng_state))
            world.state.status = status
            world.state.game_mode = int(GameMode.QUESTS)
            world.state.demo_mode_active = bool(demo_mode_active)
            world.state.hardcore = bool(hardcore)
            world.state.preserve_bugs = bool(preserve_bugs)
            world.state.quest_stage_major = int(quest_stage_major_state)
            world.state.quest_stage_minor = int(quest_stage_minor_state)
            world.state.perk_selection.pending_count = int(perk_pending)
            world.state.perk_selection.choices = list(perk_choices)
            world.state.perk_selection.choices_dirty = bool(perk_choices_dirty)
            world.state.perk_intervals.man_bomb = float(man_bomb_interval)
            world.state.perk_intervals.fire_cough = float(fire_cough_interval)
            world.state.perk_intervals.hot_tempered = float(hot_tempered_interval)

            reset_players(
                world.players,
                world_size=float(world_size),
                player_count=int(replay.header.player_count),
            )
            for player in world.players:
                weapon_assign_player(player, int(quest_start_weapon_id))
                if int(quest_start_weapon_id) == int(WeaponId.PISTOL):
                    player.clip_size = max(12, int(player.clip_size))
                    if float(player.ammo) < 12.0:
                        player.ammo = 12.0
            world.spawn_env = replace(
                world.spawn_env,
                difficulty_level=max(1, int(world.spawn_env.difficulty_level)),
            )
            world.creatures.env = world.spawn_env
            world.creatures.effects = world.state.effects
            world.creatures.reset()
            world.creatures.capture_spawn_events_authoritative = bool(capture_spawn_events_authoritative)

            fx_queue.clear()
            fx_queue_rotated.clear()

            if session_quest is not None:
                session_quest.spawn_entries = tuple(reset_spawn_entries)
                session_quest.spawn_timeline_ms = 0.0
                session_quest.no_creatures_timer_ms = 0.0
                session_quest.completion_transition_ms = -1.0
            pending_capture_state_reset = False

        def _on_capture_state_transition(
            target_state: int,
            _before_state: int | None,
            _after_state: int | None,
        ) -> None:
            nonlocal pending_capture_state_reset
            if int(target_state) != 12:
                return
            pending_capture_state_reset = True

        tick_begin = max(0, int(bootstrap_start_tick)) if bootstrap_start_tick is not None else 0

        if bootstrap_start_tick is not None and session_quest is not None:
            bootstrap_tick = int(bootstrap_start_tick)
            bootstrap_dt = resolve_dt_frame(
                tick_index=bootstrap_tick,
                default_dt_frame=float(default_dt_frame),
                dt_frame_overrides=dt_frame_overrides,
            )
            bootstrap_dt_ms = float(bootstrap_dt) * 1000.0
            if bootstrap_tick in events_by_tick:
                bootstrap_events = events_by_tick[bootstrap_tick]
            else:
                bootstrap_events = []
            for event in bootstrap_events:
                if not (isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND):
                    continue
                payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
                if payload is None:
                    break
                quest_session = payload["quest_session"] if "quest_session" in payload else None
                if isinstance(quest_session, dict):
                    quest_session_data = cast(dict[str, object], quest_session)
                    timeline_ms = (
                        quest_session_data["spawn_timeline_ms"] if "spawn_timeline_ms" in quest_session_data else None
                    )
                    if isinstance(timeline_ms, (int, float)):
                        session_quest.spawn_timeline_ms = max(0.0, float(timeline_ms) - float(bootstrap_dt_ms))
                    no_creatures_timer_ms = (
                        quest_session_data["no_creatures_timer_ms"]
                        if "no_creatures_timer_ms" in quest_session_data
                        else None
                    )
                    if isinstance(no_creatures_timer_ms, (int, float)):
                        session_quest.no_creatures_timer_ms = max(
                            0.0,
                            float(no_creatures_timer_ms) - float(bootstrap_dt_ms),
                        )
                    completion_transition_ms = (
                        quest_session_data["completion_transition_ms"]
                        if "completion_transition_ms" in quest_session_data
                        else None
                    )
                    if isinstance(completion_transition_ms, (int, float)):
                        completion_value = float(completion_transition_ms)
                        if completion_value >= 0.0:
                            completion_value = max(0.0, float(completion_value) - float(bootstrap_dt_ms))
                        session_quest.completion_transition_ms = float(completion_value)
                break

    out: list[CreatureTrajectoryRow] = []
    for tick_index in range(int(tick_begin), int(end_tick) + 1):
        tick_key = int(tick_index)
        if mode == int(GameMode.QUESTS) and pending_capture_state_reset:
            _apply_capture_state_reset()

        state = world.state
        state.game_mode = int(mode)
        state.demo_mode_active = False
        if inter_tick_rand_draws_by_tick is not None:
            draws = (
                inter_tick_rand_draws_by_tick[int(tick_index)]
                if int(tick_index) in inter_tick_rand_draws_by_tick
                else None
            )
            if draws is None:
                draws = int(inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                state.rng.rand()
        dt_tick = resolve_dt_frame(
            tick_index=tick_key,
            default_dt_frame=float(default_dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=tick_key,
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
        )
        if tick_key in events_by_tick:
            tick_events = events_by_tick[tick_key]
        else:
            tick_events = []
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )
        apply_replay_tick_events(
            pre_step_events,
            tick_index=tick_key,
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(mode),
            strict_events=False,
            on_capture_state_transition=(_on_capture_state_transition if mode == int(GameMode.QUESTS) else None),
        )
        if mode == int(GameMode.QUESTS) and pending_capture_state_reset:
            _apply_capture_state_reset()

        player_inputs = _decode_inputs_for_tick(
            replay=replay,
            tick_index=tick_key,
        )
        if session_survival is not None:
            session_survival.step_tick(
                dt_frame=float(dt_tick),
                dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
                inputs=player_inputs,
                trace_rng=False,
            )
        elif session_quest is not None:
            session_quest.step_tick(
                dt_frame=float(dt_tick),
                dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
                inputs=player_inputs,
                trace_rng=False,
            )

        if post_step_events:
            apply_replay_tick_events(
                post_step_events,
                tick_index=tick_key,
                dt_frame=float(dt_tick),
                world=world,
                game_mode_id=int(mode),
                strict_events=False,
                on_capture_state_transition=(_on_capture_state_transition if mode == int(GameMode.QUESTS) else None),
            )
        if mode == int(GameMode.QUESTS):
            world.creatures.finalize_post_render_lifecycle()

        sample = capture_rows[tick_key] if tick_key in capture_rows else None
        if sample is not None and int(tick_index) >= int(start_tick):
            if not (0 <= int(creature_index) < len(world.creatures.entries)):
                break
            creature = world.creatures.entries[int(creature_index)]
            cap_pos_obj = sample["pos"]
            cap_pos = cast("dict[str, object]", cap_pos_obj)
            cap_x = float(cast("Any", cap_pos["x"]))
            cap_y = float(cast("Any", cap_pos["y"]))
            cap_type_id = int(sample["type_id"])
            cap_flags = int(sample["flags"])
            cap_active = bool(int(sample["active"]) != 0)
            cap_target_player = int(sample["target_player"])
            cap_hp = float(sample["hp"])
            cap_hitbox = float(sample["hitbox_size"])
            cap_collision_flag = int(sample["collision_flag"])
            cap_state_flag = int(sample["state_flag"])
            cap_heading = float(sample["heading"])
            cap_target_heading = float(sample["target_heading"])
            rw_x = float(creature.pos.x)
            rw_y = float(creature.pos.y)
            dx = rw_x - cap_x
            dy = rw_y - cap_y
            out.append(
                CreatureTrajectoryRow(
                    tick=int(tick_index),
                    cap_type_id=cap_type_id,
                    rw_type_id=int(creature.type_id),
                    cap_flags=cap_flags,
                    rw_flags=int(creature.flags),
                    cap_active=cap_active,
                    rw_active=bool(creature.active),
                    cap_target_player=cap_target_player,
                    rw_target_player=int(creature.target_player),
                    rw_ai_mode=int(creature.ai_mode),
                    cap_hp=cap_hp,
                    rw_hp=float(creature.hp),
                    hp_delta=float(creature.hp) - cap_hp,
                    cap_hitbox=cap_hitbox,
                    rw_hitbox=float(creature.hitbox_size),
                    hitbox_delta=float(creature.hitbox_size) - cap_hitbox,
                    cap_collision_flag=cap_collision_flag,
                    cap_state_flag=cap_state_flag,
                    rw_plague_infected=bool(creature.plague_infected),
                    rw_attack_cooldown=float(creature.attack_cooldown),
                    rw_move_scale=float(creature.move_scale),
                    cap_heading=cap_heading,
                    cap_target_heading=cap_target_heading,
                    rw_heading=float(creature.heading),
                    rw_target_heading=float(creature.target_heading),
                    rw_force_target=int(creature.force_target),
                    rw_target_x=float(creature.target.x),
                    rw_target_y=float(creature.target.y),
                    rw_target_dist=float((creature.target - creature.pos).length()),
                    rw_orbit_radius=float(creature.orbit_radius),
                    cap_x=cap_x,
                    cap_y=cap_y,
                    rw_x=rw_x,
                    rw_y=rw_y,
                    dx=dx,
                    dy=dy,
                    drift_mag=math.hypot(dx, dy),
                ),
            )

        if inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                state.rng.rand()
    return out


def _print_summary(rows: list[CreatureTrajectoryRow], *, print_every: int) -> None:
    if not rows:
        print("rows=0")
        return

    print(f"rows={len(rows)} tick_range={rows[0].tick}-{rows[-1].tick}")
    first_dead = next((row for row in rows if row.cap_hp <= 0.0), None)
    first_hitbox_lt16 = next((row for row in rows if row.cap_hitbox < 16.0), None)
    print(f"first_dead_tick={first_dead.tick if first_dead is not None else 'none'}")
    print(f"first_hitbox_lt16_tick={first_hitbox_lt16.tick if first_hitbox_lt16 is not None else 'none'}")
    for threshold in (0.01, 0.02, 0.05, 0.1):
        first = next((row for row in rows if row.drift_mag >= threshold), None)
        tick = first.tick if first is not None else "none"
        drift = f"{first.drift_mag:.6f}" if first is not None else "none"
        print(f"first_drift_ge_{threshold:.2f}={tick} mag={drift}")

    max_row = max(rows, key=lambda row: row.drift_mag)
    print(
        f"max_drift={max_row.drift_mag:.6f} tick={max_row.tick} dx={max_row.dx:.6f} dy={max_row.dy:.6f}",
    )

    transitions = 0
    print("\nai_mode_transitions:")
    prev_mode = rows[0].rw_ai_mode
    prev_target = rows[0].rw_target_player
    prev_flags = rows[0].rw_flags
    for row in rows[1:]:
        if row.rw_ai_mode != prev_mode or row.rw_target_player != prev_target or row.rw_flags != prev_flags:
            transitions += 1
            print(
                f"  tick={row.tick:4d} "
                f"ai_mode {prev_mode}->{row.rw_ai_mode} "
                f"target_player {prev_target}->{row.rw_target_player} "
                f"flags {prev_flags}->{row.rw_flags} "
                f"drift={row.drift_mag:.6f}",
            )
            prev_mode = row.rw_ai_mode
            prev_target = row.rw_target_player
            prev_flags = row.rw_flags
    if transitions == 0:
        print("  none")

    print("\nrows_sample:")
    step = max(1, int(print_every))
    for row in rows:
        if row.tick == rows[-1].tick or row.tick == rows[0].tick or row.tick % step == 0:
            print(
                f"  tick={row.tick:4d} "
                f"dx={row.dx:+.6f} dy={row.dy:+.6f} mag={row.drift_mag:.6f} "
                f"hp(e/a)={row.cap_hp:.3f}/{row.rw_hp:.3f} "
                f"hitbox(e/a)={row.cap_hitbox:.6f}/{row.rw_hitbox:.6f} "
                f"active(e/a)={int(row.cap_active)}/{int(row.rw_active)} "
                f"ai_mode={row.rw_ai_mode} target_player={row.rw_target_player}",
            )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace one capture creature slot across ticks and compare capture vs rewrite trajectory.",
    )
    parser.add_argument("capture", type=Path, help="capture file (.json/.json.gz)")
    parser.add_argument("--creature-index", type=int, required=True, help="capture creature slot index to trace")
    parser.add_argument("--start-tick", type=int, default=0, help="first tick to include in output")
    parser.add_argument("--end-tick", type=int, required=True, help="last tick to simulate/included output")
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="extra rand draws between ticks (native console loop parity)",
    )
    parser.add_argument("--print-every", type=int, default=50, help="print every N ticks in summary")
    parser.add_argument(
        "--json-out",
        nargs="?",
        default=None,
        const=_JSON_OUT_AUTO,
        help=(
            "optional JSON output path "
            "(default when flag is present: artifacts/frida/reports/creature<IDX>_<START>_<END>_latest.json)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    start_tick = max(0, int(args.start_tick))
    end_tick = max(0, int(args.end_tick))
    json_out_path = _resolve_json_out_path(
        args.json_out,
        creature_index=int(args.creature_index),
        start_tick=int(start_tick),
        end_tick=int(end_tick),
    )
    if end_tick < start_tick:
        raise ValueError(f"end_tick must be >= start_tick (got start={start_tick}, end={end_tick})")

    rows = trace_creature_trajectory(
        capture_path=Path(args.capture),
        creature_index=int(args.creature_index),
        start_tick=int(start_tick),
        end_tick=int(end_tick),
        inter_tick_rand_draws=max(0, int(args.inter_tick_rand_draws)),
    )
    _print_summary(rows, print_every=max(1, int(args.print_every)))

    if json_out_path is not None:
        payload = {
            "capture": str(Path(args.capture)),
            "creature_index": int(args.creature_index),
            "start_tick": int(start_tick),
            "end_tick": int(end_tick),
            "inter_tick_rand_draws": max(0, int(args.inter_tick_rand_draws)),
            "rows": [asdict(row) for row in rows],
        }
        out_path = json_out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\njson_report={out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
