from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import msgspec
from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    build_capture_dt_frame_overrides,
    build_capture_dt_frame_ms_i32_overrides,
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
    _resolve_dt_frame,
    _should_apply_world_dt_steps_for_replay,
)
from crimson.sim.sessions import SurvivalDeterministicSession
from crimson.sim.world_state import WorldState

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
    rw_heading: float
    rw_target_heading: float
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
        return _DEFAULT_JSON_OUT_DIR / (
            f"creature{int(creature_index)}_{int(start_tick)}_{int(end_tick)}_latest.json"
        )
    return Path(value)


def _read_capture_creature_samples(
    *,
    capture: object,
    creature_index: int,
    start_tick: int,
    end_tick: int,
) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    ticks = getattr(capture, "ticks", None)
    if not isinstance(ticks, list):
        return out
    for tick_row in ticks:
        tick = int(getattr(tick_row, "tick_index", -1))
        if tick < int(start_tick) or tick > int(end_tick):
            continue
        obj = msgspec.to_builtins(tick_row)
        if not isinstance(obj, dict):
            continue
        samples = obj.get("samples") if isinstance(obj.get("samples"), dict) else {}
        creatures = samples.get("creatures") if isinstance(samples.get("creatures"), list) else []
        for row in creatures:  # ty:ignore[not-iterable]
            if not isinstance(row, dict):
                continue
            if int(row.get("index", -1)) != int(creature_index):
                continue
            out[int(tick)] = row
            break
    return out


def _load_capture_events(replay: Any) -> tuple[dict[int, list[object]], bool]:
    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
    return events_by_tick, original_capture_replay


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
        out.append(
            PlayerInput(
                move=Vec2(float(mx), float(my)),
                aim=Vec2(float(ax), float(ay)),
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
                move_forward_pressed=None,
                move_backward_pressed=None,
                turn_left_pressed=None,
                turn_right_pressed=None,
            )
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
    if mode != int(GameMode.SURVIVAL):
        raise ValueError(f"trajectory trace currently supports survival mode only (got mode={mode})")

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

    events_by_tick, original_capture_replay = _load_capture_events(replay)
    dt_frame_overrides = build_capture_dt_frame_overrides(capture, tick_rate=int(replay.header.tick_rate))
    dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
    session.apply_world_dt_steps = _should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=dt_frame_overrides,
        dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
    )
    default_dt_frame = 1.0 / float(int(replay.header.tick_rate))

    out: list[CreatureTrajectoryRow] = []
    for tick_index in range(int(end_tick) + 1):
        dt_tick = _resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(default_dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = dt_frame_ms_i32_overrides.get(int(tick_index))
        _apply_tick_events(
            events_by_tick.get(int(tick_index), []),
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            strict_events=False,
        )
        player_inputs = _decode_inputs_for_tick(
            replay=replay,
            tick_index=int(tick_index),
        )
        session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=player_inputs,
            trace_rng=False,
        )

        sample = capture_rows.get(int(tick_index))
        if sample is not None and int(tick_index) >= int(start_tick):
            if not (0 <= int(creature_index) < len(world.creatures.entries)):
                break
            creature = world.creatures.entries[int(creature_index)]
            cap_pos = sample.get("pos") if isinstance(sample.get("pos"), dict) else {}
            cap_x = float(cap_pos.get("x", 0.0))  # ty:ignore[possibly-missing-attribute]
            cap_y = float(cap_pos.get("y", 0.0))  # ty:ignore[possibly-missing-attribute]
            rw_x = float(creature.pos.x)
            rw_y = float(creature.pos.y)
            dx = rw_x - cap_x
            dy = rw_y - cap_y
            out.append(
                CreatureTrajectoryRow(
                    tick=int(tick_index),
                    cap_type_id=int(sample.get("type_id", -1)),
                    rw_type_id=int(creature.type_id),
                    cap_flags=int(sample.get("flags", 0)),
                    rw_flags=int(creature.flags),
                    cap_active=bool(int(sample.get("active", 0)) != 0),
                    rw_active=bool(creature.active),
                    cap_target_player=int(sample.get("target_player", -1)),
                    rw_target_player=int(creature.target_player),
                    rw_ai_mode=int(creature.ai_mode),
                    cap_hp=float(sample.get("hp", 0.0)),
                    rw_hp=float(creature.hp),
                    hp_delta=float(creature.hp) - float(sample.get("hp", 0.0)),
                    cap_hitbox=float(sample.get("hitbox_size", 0.0)),
                    rw_hitbox=float(creature.hitbox_size),
                    hitbox_delta=float(creature.hitbox_size) - float(sample.get("hitbox_size", 0.0)),
                    cap_collision_flag=int(sample.get("collision_flag", 0)),
                    cap_state_flag=int(sample.get("state_flag", 0)),
                    rw_plague_infected=bool(creature.plague_infected),
                    rw_attack_cooldown=float(creature.attack_cooldown),
                    rw_move_scale=float(creature.move_scale),
                    rw_heading=float(creature.heading),
                    rw_target_heading=float(creature.target_heading),
                    rw_orbit_radius=float(creature.orbit_radius),
                    cap_x=cap_x,
                    cap_y=cap_y,
                    rw_x=rw_x,
                    rw_y=rw_y,
                    dx=dx,
                    dy=dy,
                    drift_mag=math.hypot(dx, dy),
                )
            )

        draws = max(0, int(inter_tick_rand_draws))
        for _ in range(draws):
            world.state.rng.rand()
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
        "max_drift="
        f"{max_row.drift_mag:.6f} tick={max_row.tick} "
        f"dx={max_row.dx:.6f} dy={max_row.dy:.6f}"
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
                f"drift={row.drift_mag:.6f}"
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
                f"ai_mode={row.rw_ai_mode} target_player={row.rw_target_player}"
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
