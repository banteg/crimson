#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import msgspec
from deepdiff import DeepDiff
from rich.console import Console
from rich.text import Text

from crimson.bonuses.ids import BonusId
from crimson.replay import ReplayCodecError, load_replay
from crimson.replay.diagnostic_trace_native import (
    BONUS_ID_COUNT,
    PERK_COUNT_SIZE,
    REPLAY_TICK_TRACE_SCHEMA_VERSION,
    ReplayTickTraceJsonRow,
    decode_replay_tick_trace_json_row,
    decode_replay_tick_trace_jsonl,
)
from crimson.sim.driver.replay_runner import ReplayRunnerError, run_survival_replay

# Python currently cannot observe these natively in replay_runner world callbacks.
_UNSUPPORTED_COMPARE_PATHS: set[str] = {
    "debug.debug_pending_nuke",
    "debug.debug_nuke_kills_last",
    "debug.debug_nuke_tick_last",
    "debug.debug_nuke_kill_index_sum",
    "debug.debug_last_picked_bonus_id",
    "debug.debug_last_picked_bonus_amount",
    "projectiles.projectile_first_hit_creature_index",
    "projectiles.projectile_first_hit_projectile_index",
}


def _default_runtime_dir() -> Path:
    env_runtime = os.environ.get("CRIMSON_RUNTIME_DIR")
    if env_runtime:
        return Path(env_runtime)
    env_base = os.environ.get("CRIMSON_BASE_DIR")
    if env_base:
        return Path(env_base)
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "banteg" / "crimsonland"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "banteg" / "crimsonland"
        return Path(".")
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "banteg" / "crimsonland"
    return home / ".local" / "share" / "banteg" / "crimsonland"


def _resolve_replay_path(replay_arg: str, *, base_dir: Path) -> Path:
    replay = Path(replay_arg)
    if replay.is_file():
        return replay

    if not replay.is_absolute() and len(replay.parts) == 1:
        candidate = base_dir / "replays" / replay
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(replay_arg)


def _f32_bits(value: float) -> int:
    return int(struct.unpack("<I", struct.pack("<f", float(value)))[0])


def _add_projectile_type_count(entries: list[dict[str, int]], type_id: int) -> None:
    idx = 0
    while idx < len(entries) and int(entries[idx]["type_id"]) < int(type_id):
        idx += 1
    if idx < len(entries) and int(entries[idx]["type_id"]) == int(type_id):
        entries[idx]["count"] = int(entries[idx]["count"]) + 1
        return
    entries.insert(idx, {"type_id": int(type_id), "count": 1})


def _add_bonus_active_entry(entries: list[dict[str, int]], bonus_id: int, amount: int) -> None:
    idx = 0
    while idx < len(entries) and int(entries[idx]["bonus_id"]) < int(bonus_id):
        idx += 1
    entries.insert(idx, {"bonus_id": int(bonus_id), "amount": int(amount)})


def _bonus_timer_ms(seconds: float) -> int:
    if not (float(seconds) > 0.0):
        return 0
    value = int(round(float(seconds) * 1000.0))
    if value < 0:
        return 0
    return int(value)


def _build_python_row(
    *,
    tick_index: int,
    elapsed_ms: float,
    world: object,
    events: object,
    rng_marks: dict[str, int],
) -> ReplayTickTraceJsonRow:
    state = getattr(world, "state")
    players = list(getattr(world, "players"))
    creatures_pool = getattr(world, "creatures")
    creatures_entries = list(getattr(creatures_pool, "entries"))
    projectiles_entries = list(getattr(state.projectiles, "entries"))
    bonus_pool_entries = list(getattr(state.bonus_pool, "entries"))

    player = players[0] if players else None

    projectile_count = 0
    projectile_type_counts: list[dict[str, int]] = []
    projectile_entries: list[dict[str, object]] = []

    for idx, entry in enumerate(projectiles_entries):
        if not bool(getattr(entry, "active")):
            continue

        projectile_count += 1

        type_id = int(getattr(entry, "type_id"))
        owner_legacy = int(entry.owner.to_legacy())

        _add_projectile_type_count(projectile_type_counts, type_id)

        projectile_entries.append(
            {
                "index": int(idx),
                "type_id": int(type_id),
                "pos_x_bits": _f32_bits(float(getattr(entry.pos, "x"))),
                "pos_y_bits": _f32_bits(float(getattr(entry.pos, "y"))),
                "origin_x_bits": _f32_bits(float(getattr(entry.origin, "x"))),
                "origin_y_bits": _f32_bits(float(getattr(entry.origin, "y"))),
                "life_timer_bits": _f32_bits(float(getattr(entry, "life_timer"))),
                "damage_pool_bits": _f32_bits(float(getattr(entry, "damage_pool"))),
                "angle_bits": _f32_bits(float(getattr(entry, "angle"))),
                "speed_scale_bits": _f32_bits(float(getattr(entry, "speed_scale"))),
                "owner_legacy": int(owner_legacy),
                "hits_players": bool(getattr(entry, "hits_players")),
            },
        )

    creature_entries: list[dict[str, object]] = []

    for idx, creature in enumerate(creatures_entries):
        if not bool(getattr(creature, "active")):
            continue

        type_id = int(getattr(creature, "type_id"))
        creature_flags = int(getattr(creature, "flags"))

        creature_entries.append(
            {
                "index": int(idx),
                "type_id": int(type_id),
                "flags": int(creature_flags),
                "ai_mode": int(getattr(creature, "ai_mode")),
                "link_index": int(getattr(creature, "link_index")),
                "pos_x_bits": _f32_bits(float(getattr(creature.pos, "x"))),
                "pos_y_bits": _f32_bits(float(getattr(creature.pos, "y"))),
                "target_x_bits": _f32_bits(float(getattr(creature.target, "x"))),
                "target_y_bits": _f32_bits(float(getattr(creature.target, "y"))),
                "heading_bits": _f32_bits(float(getattr(creature, "heading"))),
                "target_heading_bits": _f32_bits(float(getattr(creature, "target_heading"))),
                "hp_bits": _f32_bits(float(getattr(creature, "hp"))),
                "lifecycle_stage_bits": _f32_bits(float(getattr(creature, "lifecycle_stage"))),
                "size_bits": _f32_bits(float(getattr(creature, "size"))),
                "attack_cooldown_bits": _f32_bits(float(getattr(creature, "attack_cooldown"))),
            },
        )

    bonus_active_entries: list[dict[str, int]] = []
    bonus_active_count = 0
    for entry in bonus_pool_entries:
        bonus_id = int(getattr(entry, "bonus_id"))
        if bonus_id == int(BonusId.UNUSED):
            continue
        bonus_active_count += 1
        _add_bonus_active_entry(bonus_active_entries, bonus_id, int(getattr(entry, "amount")))

    bonus_timer_ms_by_id = [0] * int(BONUS_ID_COUNT)
    bonus_timer_ms_by_id[int(BonusId.WEAPON_POWER_UP)] = _bonus_timer_ms(float(state.bonuses.weapon_power_up))
    bonus_timer_ms_by_id[int(BonusId.REFLEX_BOOST)] = _bonus_timer_ms(float(state.bonuses.reflex_boost))
    bonus_timer_ms_by_id[int(BonusId.ENERGIZER)] = _bonus_timer_ms(float(state.bonuses.energizer))
    bonus_timer_ms_by_id[int(BonusId.DOUBLE_EXPERIENCE)] = _bonus_timer_ms(float(state.bonuses.double_experience))
    bonus_timer_ms_by_id[int(BonusId.FREEZE)] = _bonus_timer_ms(float(state.bonuses.freeze))

    if player is None:
        player_perk_counts = [0] * int(PERK_COUNT_SIZE)
        player_payload = {
            "player_weapon_id": 0,
            "player_ammo_bits": _f32_bits(0.0),
            "player_health_bits": _f32_bits(0.0),
            "player_pos_x_bits": _f32_bits(0.0),
            "player_pos_y_bits": _f32_bits(0.0),
            "player_aim_x_bits": _f32_bits(0.0),
            "player_aim_y_bits": _f32_bits(0.0),
            "player_heading_bits": _f32_bits(0.0),
            "player_aim_heading_bits": _f32_bits(0.0),
            "player_move_speed_bits": _f32_bits(0.0),
            "player_turn_speed_bits": _f32_bits(0.0),
            "player_level": 0,
            "player_experience": 0,
            "player_reload_active": False,
            "player_reload_timer_bits": _f32_bits(0.0),
            "player_shot_cooldown_bits": _f32_bits(0.0),
            "player_shot_seq": 0,
            "player_perk_counts": player_perk_counts,
            "player_hot_tempered_timer_bits": _f32_bits(0.0),
            "player_shield_timer_bits": _f32_bits(0.0),
            "player_man_bomb_timer_bits": _f32_bits(0.0),
            "player_fire_cough_timer_bits": _f32_bits(0.0),
            "player_living_fortress_timer_bits": _f32_bits(0.0),
            "perk_interval_hot_tempered_bits": _f32_bits(float(state.perk_intervals.hot_tempered)),
            "perk_interval_man_bomb_bits": _f32_bits(float(state.perk_intervals.man_bomb)),
            "perk_interval_fire_cough_bits": _f32_bits(float(state.perk_intervals.fire_cough)),
        }
        score_xp = 0
    else:
        player_perk_counts = [int(value) for value in list(player.perk_counts)[0 : int(PERK_COUNT_SIZE)]]
        if len(player_perk_counts) < int(PERK_COUNT_SIZE):
            player_perk_counts += [0] * (int(PERK_COUNT_SIZE) - len(player_perk_counts))
        player_payload = {
            "player_weapon_id": int(player.weapon_id),
            "player_ammo_bits": _f32_bits(float(player.ammo)),
            "player_health_bits": _f32_bits(float(player.health)),
            "player_pos_x_bits": _f32_bits(float(player.pos.x)),
            "player_pos_y_bits": _f32_bits(float(player.pos.y)),
            "player_aim_x_bits": _f32_bits(float(player.aim.x)),
            "player_aim_y_bits": _f32_bits(float(player.aim.y)),
            "player_heading_bits": _f32_bits(float(player.heading)),
            "player_aim_heading_bits": _f32_bits(float(player.aim_heading)),
            "player_move_speed_bits": _f32_bits(float(player.move_speed)),
            "player_turn_speed_bits": _f32_bits(float(player.turn_speed)),
            "player_level": int(player.level),
            "player_experience": int(player.experience),
            "player_reload_active": bool(player.reload_active),
            "player_reload_timer_bits": _f32_bits(float(player.reload_timer)),
            "player_shot_cooldown_bits": _f32_bits(float(player.shot_cooldown)),
            "player_shot_seq": int(player.shot_seq),
            "player_perk_counts": player_perk_counts,
            "player_hot_tempered_timer_bits": _f32_bits(float(player.hot_tempered_timer)),
            "player_shield_timer_bits": _f32_bits(float(player.shield_timer)),
            "player_man_bomb_timer_bits": _f32_bits(float(player.man_bomb_timer)),
            "player_fire_cough_timer_bits": _f32_bits(float(player.fire_cough_timer)),
            "player_living_fortress_timer_bits": _f32_bits(float(player.living_fortress_timer)),
            "perk_interval_hot_tempered_bits": _f32_bits(float(state.perk_intervals.hot_tempered)),
            "perk_interval_man_bomb_bits": _f32_bits(float(state.perk_intervals.man_bomb)),
            "perk_interval_fire_cough_bits": _f32_bits(float(state.perk_intervals.fire_cough)),
        }
        score_xp = int(player.experience)

    hits = list(getattr(events, "hits"))
    first_hit_creature_index = -1
    first_hit_projectile_index = -1
    first_hit_type_id = 0
    first_hit_origin_x_bits = _f32_bits(0.0)
    first_hit_origin_y_bits = _f32_bits(0.0)
    first_hit_pos_x_bits = _f32_bits(0.0)
    first_hit_pos_y_bits = _f32_bits(0.0)
    first_hit_target_size_bits = _f32_bits(0.0)
    first_hit_target_x_bits = _f32_bits(0.0)
    first_hit_target_y_bits = _f32_bits(0.0)
    if hits:
        first = hits[0]
        first_hit_type_id = int(first.type_id)
        first_hit_origin_x_bits = _f32_bits(float(first.origin.x))
        first_hit_origin_y_bits = _f32_bits(float(first.origin.y))
        first_hit_pos_x_bits = _f32_bits(float(first.hit.x))
        first_hit_pos_y_bits = _f32_bits(float(first.hit.y))
        first_hit_target_x_bits = _f32_bits(float(first.target.x))
        first_hit_target_y_bits = _f32_bits(float(first.target.y))
        target_size = 0.0
        for creature in creatures_entries:
            if not bool(getattr(creature, "active")):
                continue
            if abs(float(creature.pos.x) - float(first.target.x)) < 1e-4 and abs(float(creature.pos.y) - float(first.target.y)) < 1e-4:
                target_size = float(creature.size)
                break
        first_hit_target_size_bits = _f32_bits(target_size)

    rng_state = int(state.rng.state)
    row_payload = {
        "schema_version": int(REPLAY_TICK_TRACE_SCHEMA_VERSION),
        "tick_index": int(tick_index),
        "timing": {
            "elapsed_ms": int(round(float(elapsed_ms))),
        },
        "rng": {
            "rng_state": int(rng_state),
            "rng_after_perk_effects": int(rng_marks["ws_after_perk_effects"]),
            "rng_after_creatures": int(rng_marks["ws_after_creatures"]),
            "rng_after_projectiles": int(rng_marks["ws_after_projectiles"]),
            "rng_after_secondary_projectiles": int(rng_marks["ws_after_secondary_projectiles"]),
            "rng_after_particles": int(rng_marks["ws_after_particles"]),
            "rng_after_player_update": int(rng_marks["ws_after_player_update"]),
            "rng_after_stage_spawns": int(rng_marks["after_stage_spawns"]),
            "rng_after_wave_spawns": int(rng_marks["after_wave_spawns"]),
            "rng_after_spawns": int(rng_marks["after_wave_spawns"]),
            "rng_after_bonus_update": int(rng_marks["ws_after_bonus_update"]),
        },
        "summary": {
            "score_xp": int(score_xp),
            "kills": int(creatures_pool.kill_count),
            "shots_fired_p0": int(state.shots_fired[0] if len(state.shots_fired) > 0 else 0),
            "creature_count": int(sum(1 for creature in creatures_entries if bool(getattr(creature, "active")))),
            "perk_pending": int(state.perk_selection.pending_count),
        },
        "player": player_payload,
        "bonuses": {
            "bonus_timer_ms_by_id": bonus_timer_ms_by_id,
            "bonus_active_count": int(bonus_active_count),
            "active_entries": bonus_active_entries,
        },
        "projectiles": {
            "projectile_count": int(projectile_count),
            "projectile_hit_count": int(len(hits)),
            "projectile_first_hit_creature_index": int(first_hit_creature_index),
            "projectile_first_hit_projectile_index": int(first_hit_projectile_index),
            "projectile_first_hit_type_id": int(first_hit_type_id),
            "projectile_first_hit_origin_x_bits": int(first_hit_origin_x_bits),
            "projectile_first_hit_origin_y_bits": int(first_hit_origin_y_bits),
            "projectile_first_hit_pos_x_bits": int(first_hit_pos_x_bits),
            "projectile_first_hit_pos_y_bits": int(first_hit_pos_y_bits),
            "projectile_first_hit_target_size_bits": int(first_hit_target_size_bits),
            "projectile_first_hit_target_x_bits": int(first_hit_target_x_bits),
            "projectile_first_hit_target_y_bits": int(first_hit_target_y_bits),
            "projectile_type_counts": projectile_type_counts,
            "entries": projectile_entries,
        },
        "creatures": {
            "entries": creature_entries,
        },
        "debug": {
            "debug_pending_nuke": 0,
            "debug_nuke_kills_last": 0,
            "debug_nuke_tick_last": -1,
            "debug_nuke_kill_index_sum": 0,
            "debug_last_picked_bonus_id": 0,
            "debug_last_picked_bonus_amount": 0,
        },
    }

    payload = json.dumps(row_payload, separators=(",", ":")).encode("utf-8")
    return decode_replay_tick_trace_json_row(payload, field=f"python trace row {int(tick_index) + 1}")


def _build_python_trace_rows(replay_path: Path) -> list[ReplayTickTraceJsonRow]:
    replay = load_replay(replay_path.read_bytes())
    rows: list[ReplayTickTraceJsonRow] = []

    def _on_tick_trace(
        tick_index: int,
        world: object,
        elapsed_ms: float,
        events: object,
        rng_marks: dict[str, int],
    ) -> None:
        row = _build_python_row(
            tick_index=int(tick_index),
            elapsed_ms=float(elapsed_ms),
            world=world,
            events=events,
            rng_marks=rng_marks,
        )
        rows.append(row)

    run_survival_replay(
        replay,
        warn_on_version_mismatch=False,
        strict_events=False,
        tick_trace_observer=_on_tick_trace,
    )

    rows.sort(key=lambda row: int(row.tick_index))
    return rows


def _load_trace_jsonl(trace_path: Path) -> list[ReplayTickTraceJsonRow]:
    return decode_replay_tick_trace_jsonl(trace_path)


def _write_trace_jsonl(trace_path: Path, rows: list[ReplayTickTraceJsonRow]) -> None:
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    with trace_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(msgspec.to_builtins(row), separators=(",", ":")))
            handle.write("\n")


def _run_zig_trace(
    *,
    zig_bin: Path,
    replay_path: Path,
    base_dir: Path,
    trace_path: Path,
) -> subprocess.CompletedProcess[str]:
    command = [
        str(zig_bin),
        "replay",
        "verify",
        str(replay_path),
        "--base-dir",
        str(base_dir),
        "--debug-trace-jsonl",
        str(trace_path),
    ]
    return subprocess.run(command, check=False, text=True, capture_output=True)


def _first_mismatch_value(
    expected: Any,
    actual: Any,
    *,
    path: str,
) -> tuple[str, object, object] | None:
    if path in _UNSUPPORTED_COMPARE_PATHS:
        return None

    if isinstance(expected, dict) and isinstance(actual, dict):
        if set(expected.keys()) != set(actual.keys()):
            return path, sorted(expected.keys()), sorted(actual.keys())
        for key in expected.keys():
            child_path = f"{path}.{key}" if path else str(key)
            mismatch = _first_mismatch_value(expected[key], actual[key], path=child_path)
            if mismatch is not None:
                return mismatch
        return None

    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return path, len(expected), len(actual)
        for idx, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=True)):
            child_path = f"{path}[{idx}]"
            mismatch = _first_mismatch_value(expected_item, actual_item, path=child_path)
            if mismatch is not None:
                return mismatch
        return None

    if expected != actual:
        return path, expected, actual
    return None


def _first_mismatch(
    expected_rows: list[ReplayTickTraceJsonRow],
    actual_rows: list[ReplayTickTraceJsonRow],
) -> tuple[int, str, object, object] | None:
    limit = min(len(expected_rows), len(actual_rows))
    for index in range(limit):
        expected_row = expected_rows[index]
        actual_row = actual_rows[index]
        if int(expected_row.tick_index) != int(actual_row.tick_index):
            return index, "tick_index", int(expected_row.tick_index), int(actual_row.tick_index)

        expected_obj = msgspec.to_builtins(expected_row)
        actual_obj = msgspec.to_builtins(actual_row)
        mismatch = _first_mismatch_value(expected_obj, actual_obj, path="")
        if mismatch is not None:
            path, expected_value, actual_value = mismatch
            return index, path, expected_value, actual_value

    if len(expected_rows) != len(actual_rows):
        return limit, "trace_length", len(expected_rows), len(actual_rows)
    return None


def _deepdiff_path_to_dotted(path: str) -> str:
    """Convert DeepDiff path like root['rng']['rng_state'] to rng.rng_state."""
    return path.replace("root", "").replace("['", ".").replace("']", "").replace("[", "[").replace("]", "]").lstrip(".")


def _print_state_diff(
    python_row: ReplayTickTraceJsonRow,
    zig_row: ReplayTickTraceJsonRow,
) -> None:
    python_obj = msgspec.to_builtins(python_row)
    zig_obj = msgspec.to_builtins(zig_row)

    diff = DeepDiff(
        python_obj,
        zig_obj,
        exclude_paths=[f"root['{p.split('.')[0]}']['{p.split('.')[1]}']" for p in _UNSUPPORTED_COMPARE_PATHS if '.' in p],
    )
    if not diff:
        return

    console = Console()
    console.print()
    console.print(f"[bold]state diff at tick {python_row.tick_index} (python → zig)[/bold]")

    if "values_changed" in diff:
        for path, change in diff["values_changed"].items():
            dotted = _deepdiff_path_to_dotted(path)
            old, new = change["old_value"], change["new_value"]
            line = Text()
            line.append(f"  {dotted}: ", style="bold")
            line.append(f"{old}", style="red")
            line.append(" → ")
            line.append(f"{new}", style="green")
            console.print(line)

    if "type_changes" in diff:
        for path, change in diff["type_changes"].items():
            dotted = _deepdiff_path_to_dotted(path)
            old, new = change["old_value"], change["new_value"]
            line = Text()
            line.append(f"  {dotted}: ", style="bold")
            line.append(f"{old!r}", style="red")
            line.append(" → ")
            line.append(f"{new!r}", style="green")
            console.print(line)

    for key, label in [
        ("dictionary_item_added", "added"),
        ("dictionary_item_removed", "removed"),
        ("iterable_item_added", "added"),
        ("iterable_item_removed", "removed"),
    ]:
        if key in diff:
            for path in diff[key]:
                dotted = _deepdiff_path_to_dotted(path if isinstance(path, str) else str(path))
                val = diff[key][path] if isinstance(diff[key], dict) else None
                line = Text()
                line.append(f"  {dotted}: ", style="bold")
                line.append(f"{label}", style="yellow")
                if val is not None:
                    line.append(f" = {val}")
                console.print(line)

    console.print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Python and Zig survival replay verifier tick traces.",
    )
    parser.add_argument("replay", help="replay file path or replay filename")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=_default_runtime_dir(),
        help="runtime base dir used for replay name resolution",
    )
    parser.add_argument(
        "--zig-bin",
        type=Path,
        default=Path("crimson-zig/zig-out/bin/crimson-zig"),
        help="path to the crimson-zig binary",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="skip `zig build` before running the Zig trace",
    )
    parser.add_argument(
        "--python-trace-jsonl",
        type=Path,
        default=None,
        help="optional cache path for Python trace jsonl",
    )
    parser.add_argument(
        "--refresh-python-trace",
        action="store_true",
        help="recompute Python trace even when --python-trace-jsonl exists",
    )
    args = parser.parse_args()

    replay_path = _resolve_replay_path(args.replay, base_dir=args.base_dir)
    zig_bin = Path(args.zig_bin)
    zig_root = zig_bin.parent.parent.parent

    if not args.skip_build:
        zig_exe = shutil.which("zig")
        if zig_exe is None:
            print("zig binary not found in PATH", file=sys.stderr)
            return 1
        subprocess.run([zig_exe, "build"], cwd=zig_root, check=True)

    rebuild_python_trace = True
    if (
        args.python_trace_jsonl is not None
        and args.python_trace_jsonl.is_file()
        and not args.refresh_python_trace
    ):
        try:
            python_trace_rows = _load_trace_jsonl(args.python_trace_jsonl)
            rebuild_python_trace = False
            print(f"loaded python trace cache: {args.python_trace_jsonl}")
        except (OSError, ValueError) as exc:
            print(
                f"python trace cache invalid ({args.python_trace_jsonl}): {exc}; rebuilding",
                file=sys.stderr,
            )

    if rebuild_python_trace:
        try:
            python_trace_rows = _build_python_trace_rows(replay_path)
        except (ReplayCodecError, ReplayRunnerError, RuntimeError, KeyError, ValueError) as exc:
            print(f"python trace failed: {exc}", file=sys.stderr)
            return 1
        if args.python_trace_jsonl is not None:
            _write_trace_jsonl(args.python_trace_jsonl, python_trace_rows)
            print(f"wrote python trace cache: {args.python_trace_jsonl}")

    with tempfile.TemporaryDirectory(prefix="crimson-zig-trace-") as temp_dir:
        zig_trace_path = Path(temp_dir) / "zig_trace.jsonl"
        zig_run = _run_zig_trace(
            zig_bin=zig_bin,
            replay_path=replay_path,
            base_dir=args.base_dir,
            trace_path=zig_trace_path,
        )
        if not zig_trace_path.is_file():
            print("zig trace file was not generated", file=sys.stderr)
            if zig_run.stderr.strip():
                print(zig_run.stderr.strip(), file=sys.stderr)
            return 1
        zig_trace_rows = _load_trace_jsonl(zig_trace_path)

    mismatch = _first_mismatch(python_trace_rows, zig_trace_rows)
    if mismatch is None:
        print(f"match: ticks={len(python_trace_rows)}")
        if zig_run.stderr.strip():
            print("zig stderr:")
            print(zig_run.stderr.strip())
        return 0

    tick_index, path, expected_value, actual_value = mismatch
    print(
        "divergence: "
        f"tick={tick_index} field={path} python={expected_value} zig={actual_value} "
        f"(python_ticks={len(python_trace_rows)} zig_ticks={len(zig_trace_rows)} zig_exit={zig_run.returncode})",
    )
    if zig_run.stderr.strip():
        print("zig stderr:")
        print(zig_run.stderr.strip())

    if tick_index < len(python_trace_rows) and tick_index < len(zig_trace_rows):
        _print_state_diff(python_trace_rows[tick_index], zig_trace_rows[tick_index])

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
