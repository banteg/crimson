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

from crimson.replay import ReplayCodecError, load_replay
from crimson.replay.diagnostic_trace_native import (
    REPLAY_TICK_TRACE_SCHEMA_VERSION,
    ReplayTickTraceRow,
    decode_replay_tick_trace_msgpack_row,
    decode_replay_tick_trace_msgpack_stream,
)
from crimson.sim.driver.replay_runner import ReplayRunnerError, run_survival_replay


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


def _wire_f32(value: object) -> float:
    return float(struct.unpack("<f", struct.pack("<f", float(value)))[0])


def _build_python_row(
    *,
    tick_index: int,
    elapsed_ms: float,
    world: object,
    rng_marks: dict[str, int],
) -> ReplayTickTraceRow:
    state = getattr(world, "state")
    players = list(getattr(world, "players"))
    creatures_pool = getattr(world, "creatures")
    creatures_entries = list(getattr(creatures_pool, "entries"))

    player = players[0] if players else None

    if player is None:
        player_state_payload: dict[str, object] = {
            "index": 0,
            "pos": {"x": _wire_f32(0.0), "y": _wire_f32(0.0)},
            "health": _wire_f32(0.0),
            "weapon": {
                "weapon_id": 0,
                "ammo": _wire_f32(0.0),
                "reload_active": False,
                "reload_timer": _wire_f32(0.0),
                "reload_timer_max": _wire_f32(0.0),
                "shot_cooldown": _wire_f32(0.0),
            },
            "experience": 0,
            "level": 0,
        }
        score_xp = 0
    else:
        weapon = getattr(player, "weapon", None)
        if weapon is None:
            weapon_id = int(getattr(player, "weapon_id", 0))
            ammo = _wire_f32(getattr(player, "ammo", 0.0))
            reload_active = bool(getattr(player, "reload_active", False))
            reload_timer = _wire_f32(getattr(player, "reload_timer", 0.0))
            reload_timer_max = _wire_f32(getattr(player, "reload_timer_max", 0.0))
            shot_cooldown = _wire_f32(getattr(player, "shot_cooldown", 0.0))
        else:
            weapon_id = int(getattr(weapon, "weapon_id"))
            ammo = _wire_f32(getattr(weapon, "ammo", 0.0))
            reload_active = bool(getattr(weapon, "reload_active", False))
            reload_timer = _wire_f32(getattr(weapon, "reload_timer", 0.0))
            reload_timer_max = _wire_f32(getattr(weapon, "reload_timer_max", 0.0))
            shot_cooldown = _wire_f32(getattr(weapon, "shot_cooldown", 0.0))

        player_state_payload = {
            "index": int(getattr(player, "index", 0)),
            "pos": {
                "x": _wire_f32(getattr(getattr(player, "pos"), "x", 0.0)),
                "y": _wire_f32(getattr(getattr(player, "pos"), "y", 0.0)),
            },
            "health": _wire_f32(getattr(player, "health", 0.0)),
            "weapon": {
                "weapon_id": weapon_id,
                "ammo": ammo,
                "reload_active": reload_active,
                "reload_timer": reload_timer,
                "reload_timer_max": reload_timer_max,
                "shot_cooldown": shot_cooldown,
            },
            "experience": int(getattr(player, "experience", 0)),
            "level": int(getattr(player, "level", 0)),
        }
        score_xp = int(getattr(player, "experience", 0))

    row_payload = {
        "schema_version": int(REPLAY_TICK_TRACE_SCHEMA_VERSION),
        "tick_index": int(tick_index),
        "timing": {
            "elapsed_ms": int(round(float(elapsed_ms))),
        },
        "rng": {
            "rng_state": int(getattr(state.rng, "state")),
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
            "kills": int(getattr(creatures_pool, "kill_count")),
            "shots_fired_p0": int(state.shots_fired[0] if len(state.shots_fired) > 0 else 0),
            "creature_count": int(sum(1 for creature in creatures_entries if bool(getattr(creature, "active")))),
            "perk_pending": int(state.perk_selection.pending_count),
        },
        "gameplay_state": {
            "bonuses": {
                "weapon_power_up": _wire_f32(state.bonuses.weapon_power_up),
                "reflex_boost": _wire_f32(state.bonuses.reflex_boost),
                "energizer": _wire_f32(state.bonuses.energizer),
                "double_experience": _wire_f32(state.bonuses.double_experience),
                "freeze": _wire_f32(state.bonuses.freeze),
            },
            "perk_selection": {
                "pending_count": int(state.perk_selection.pending_count),
            },
        },
        "player_state": player_state_payload,
    }

    payload = msgspec.msgpack.encode(row_payload)
    return decode_replay_tick_trace_msgpack_row(payload, field=f"python trace row {int(tick_index) + 1}")


def _build_python_trace_rows(replay_path: Path) -> list[ReplayTickTraceRow]:
    replay = load_replay(replay_path.read_bytes())
    rows: list[ReplayTickTraceRow] = []

    def _on_tick_trace(
        tick_index: int,
        world: object,
        elapsed_ms: float,
        _events: object,
        rng_marks: dict[str, int],
    ) -> None:
        row = _build_python_row(
            tick_index=int(tick_index),
            elapsed_ms=float(elapsed_ms),
            world=world,
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


def _load_trace_jsonl(trace_path: Path) -> list[ReplayTickTraceRow]:
    rows: list[ReplayTickTraceRow] = []
    raw_lines = trace_path.read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(raw_lines):
        line = str(line).strip()
        if not line:
            continue
        try:
            payload = msgspec.json.decode(line)
        except msgspec.DecodeError as exc:
            raise ValueError(f"{trace_path}.lines[{idx}] must be valid json") from exc
        if not isinstance(payload, dict):
            raise TypeError(f"{trace_path}.lines[{idx}] must be a JSON object")
        row_bytes = msgspec.msgpack.encode(payload)
        rows.append(
            decode_replay_tick_trace_msgpack_row(
                row_bytes,
                field=f"{trace_path}.lines[{idx}]",
            ),
        )
    return rows


def _write_trace_jsonl(trace_path: Path, rows: list[ReplayTickTraceRow]) -> None:
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
        "--debug-trace-msgpack",
        str(trace_path),
    ]
    return subprocess.run(command, check=False, text=True, capture_output=True)


def _first_mismatch_value(
    expected: Any,
    actual: Any,
    *,
    path: str,
) -> tuple[str, object, object] | None:
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
    expected_rows: list[ReplayTickTraceRow],
    actual_rows: list[ReplayTickTraceRow],
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
    python_row: ReplayTickTraceRow,
    zig_row: ReplayTickTraceRow,
) -> None:
    python_obj = msgspec.to_builtins(python_row)
    zig_obj = msgspec.to_builtins(zig_row)

    diff = DeepDiff(
        python_obj,
        zig_obj,
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
        zig_trace_path = Path(temp_dir) / "zig_trace.msgpack"
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
        zig_trace_rows = decode_replay_tick_trace_msgpack_stream(zig_trace_path)

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
