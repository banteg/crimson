#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TypedDict

from crimson.bonuses.ids import BonusId
from crimson.replay import ReplayCodecError, load_replay
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.sim.driver.replay_runner import ReplayRunnerError, run_survival_replay


class TickTrace(TypedDict):
    tick_index: int
    rng_state: int
    elapsed_ms: int
    score_xp: int
    kills: int
    creature_count: int
    perk_pending: int
    player_weapon_id: int
    player_ammo_q4: int
    player_health_q4: int
    player_level: int
    player_experience: int
    bonus_weapon_power_up_ms: int
    bonus_reflex_boost_ms: int
    bonus_energizer_ms: int
    bonus_double_experience_ms: int
    bonus_freeze_ms: int


TRACE_SCHEMA_VERSION = 2
TRACE_FIELDS: tuple[tuple[str, str], ...] = (
    ("rng_state", "rng.rng_state"),
    ("elapsed_ms", "timing.elapsed_ms"),
    ("score_xp", "summary.score_xp"),
    ("kills", "summary.kills"),
    ("creature_count", "summary.creature_count"),
    ("perk_pending", "summary.perk_pending"),
    ("player_weapon_id", "player.player_weapon_id"),
    ("player_ammo_q4", "player.player_ammo_q4"),
    ("player_health_q4", "player.player_health_q4"),
    ("player_level", "player.player_level"),
    ("player_experience", "player.player_experience"),
    ("bonus_weapon_power_up_ms", "bonuses.bonus_weapon_power_up_ms"),
    ("bonus_reflex_boost_ms", "bonuses.bonus_reflex_boost_ms"),
    ("bonus_energizer_ms", "bonuses.bonus_energizer_ms"),
    ("bonus_double_experience_ms", "bonuses.bonus_double_experience_ms"),
    ("bonus_freeze_ms", "bonuses.bonus_freeze_ms"),
)

BONUS_KEY_WEAPON_POWER_UP = str(BonusId.WEAPON_POWER_UP)
BONUS_KEY_REFLEX_BOOST = str(BonusId.REFLEX_BOOST)
BONUS_KEY_ENERGIZER = str(BonusId.ENERGIZER)
BONUS_KEY_DOUBLE_EXPERIENCE = str(BonusId.DOUBLE_EXPERIENCE)
BONUS_KEY_FREEZE = str(BonusId.FREEZE)


def _require_field(payload: dict[str, object], key: str, *, field: str) -> object:
    if key not in payload:
        raise ValueError(f"trace row missing required key: {field}")
    return payload[key]


def _require_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"trace row field {field} must be int, got bool")
    if isinstance(value, int):
        return int(value)
    raise TypeError(f"trace row field {field} must be int, got {type(value).__name__}")


def _require_object_dict(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"trace row field {field} must be an object")
    out: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError(f"trace row field {field} contains non-string key")
        out[key] = item
    return out


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


def _round_half_away(value: float) -> int:
    if value >= 0.0:
        return int(math.floor(value + 0.5))
    return int(math.ceil(value - 0.5))


def _q4(value: float) -> int:
    return _round_half_away(float(value) * 10000.0)


def _checkpoint_to_trace(checkpoint: ReplayCheckpoint) -> TickTrace:
    player = checkpoint.players[0]
    bonus_timers = checkpoint.bonus_timers
    return TickTrace(
        tick_index=int(checkpoint.tick_index),
        rng_state=int(checkpoint.rng_state),
        elapsed_ms=int(checkpoint.elapsed_ms),
        score_xp=int(checkpoint.score_xp),
        kills=int(checkpoint.kills),
        creature_count=int(checkpoint.creature_count),
        perk_pending=int(checkpoint.perk_pending),
        player_weapon_id=int(player.weapon_id),
        player_ammo_q4=_q4(float(player.ammo)),
        player_health_q4=_q4(float(player.health)),
        player_level=int(player.level),
        player_experience=int(player.experience),
        bonus_weapon_power_up_ms=int(bonus_timers.get(BONUS_KEY_WEAPON_POWER_UP, 0)),
        bonus_reflex_boost_ms=int(bonus_timers.get(BONUS_KEY_REFLEX_BOOST, 0)),
        bonus_energizer_ms=int(bonus_timers.get(BONUS_KEY_ENERGIZER, 0)),
        bonus_double_experience_ms=int(bonus_timers.get(BONUS_KEY_DOUBLE_EXPERIENCE, 0)),
        bonus_freeze_ms=int(bonus_timers.get(BONUS_KEY_FREEZE, 0)),
    )


def _payload_to_trace(payload: dict[str, object]) -> TickTrace:
    schema_version = _require_int(
        _require_field(payload, "schema_version", field="schema_version"),
        field="schema_version",
    )
    if schema_version != TRACE_SCHEMA_VERSION:
        raise ValueError(
            f"trace row schema_version must be {TRACE_SCHEMA_VERSION}, got {schema_version}",
        )

    timing = _require_object_dict(_require_field(payload, "timing", field="timing"), field="timing")
    rng = _require_object_dict(_require_field(payload, "rng", field="rng"), field="rng")
    summary = _require_object_dict(_require_field(payload, "summary", field="summary"), field="summary")
    player = _require_object_dict(_require_field(payload, "player", field="player"), field="player")
    bonuses = _require_object_dict(_require_field(payload, "bonuses", field="bonuses"), field="bonuses")
    projectiles = _require_object_dict(
        _require_field(payload, "projectiles", field="projectiles"),
        field="projectiles",
    )
    creatures = _require_object_dict(
        _require_field(payload, "creatures", field="creatures"),
        field="creatures",
    )
    debug = _require_object_dict(_require_field(payload, "debug", field="debug"), field="debug")

    _require_int(
        _require_field(projectiles, "projectile_state_hash", field="projectiles.projectile_state_hash"),
        field="projectiles.projectile_state_hash",
    )
    if "creature_state_hash" not in summary:
        # Legacy cache rows stored this under creatures; canonical Zig v2 uses summary.
        _require_int(
            _require_field(creatures, "creature_state_hash", field="creatures.creature_state_hash"),
            field="creatures.creature_state_hash",
        )
    else:
        _require_int(
            _require_field(summary, "creature_state_hash", field="summary.creature_state_hash"),
            field="summary.creature_state_hash",
        )
    _require_int(
        _require_field(debug, "debug_pending_nuke", field="debug.debug_pending_nuke"),
        field="debug.debug_pending_nuke",
    )
    _require_int(
        _require_field(debug, "debug_nuke_kills_last", field="debug.debug_nuke_kills_last"),
        field="debug.debug_nuke_kills_last",
    )
    _require_int(
        _require_field(debug, "debug_nuke_tick_last", field="debug.debug_nuke_tick_last"),
        field="debug.debug_nuke_tick_last",
    )
    _require_int(
        _require_field(debug, "debug_nuke_kill_index_sum", field="debug.debug_nuke_kill_index_sum"),
        field="debug.debug_nuke_kill_index_sum",
    )
    _require_int(
        _require_field(debug, "debug_last_picked_bonus_id", field="debug.debug_last_picked_bonus_id"),
        field="debug.debug_last_picked_bonus_id",
    )
    _require_int(
        _require_field(debug, "debug_last_picked_bonus_amount", field="debug.debug_last_picked_bonus_amount"),
        field="debug.debug_last_picked_bonus_amount",
    )

    return TickTrace(
        tick_index=_require_int(
            payload["tick_index"] if "tick_index" in payload else _require_field(payload, "tick", field="tick"),
            field="tick_index" if "tick_index" in payload else "tick",
        ),
        rng_state=_require_int(_require_field(rng, "rng_state", field="rng.rng_state"), field="rng.rng_state"),
        elapsed_ms=_require_int(
            _require_field(timing, "elapsed_ms", field="timing.elapsed_ms"),
            field="timing.elapsed_ms",
        ),
        score_xp=_require_int(
            _require_field(summary, "score_xp", field="summary.score_xp"),
            field="summary.score_xp",
        ),
        kills=_require_int(_require_field(summary, "kills", field="summary.kills"), field="summary.kills"),
        creature_count=_require_int(
            _require_field(summary, "creature_count", field="summary.creature_count"),
            field="summary.creature_count",
        ),
        perk_pending=_require_int(
            _require_field(summary, "perk_pending", field="summary.perk_pending"),
            field="summary.perk_pending",
        ),
        player_weapon_id=_require_int(
            _require_field(player, "player_weapon_id", field="player.player_weapon_id"),
            field="player.player_weapon_id",
        ),
        player_ammo_q4=_require_int(
            _require_field(player, "player_ammo_q4", field="player.player_ammo_q4"),
            field="player.player_ammo_q4",
        ),
        player_health_q4=_require_int(
            _require_field(player, "player_health_q4", field="player.player_health_q4"),
            field="player.player_health_q4",
        ),
        player_level=_require_int(
            _require_field(player, "player_level", field="player.player_level"),
            field="player.player_level",
        ),
        player_experience=_require_int(
            _require_field(player, "player_experience", field="player.player_experience"),
            field="player.player_experience",
        ),
        bonus_weapon_power_up_ms=_require_int(
            _require_field(bonuses, "bonus_weapon_power_up_ms", field="bonuses.bonus_weapon_power_up_ms"),
            field="bonuses.bonus_weapon_power_up_ms",
        ),
        bonus_reflex_boost_ms=_require_int(
            _require_field(bonuses, "bonus_reflex_boost_ms", field="bonuses.bonus_reflex_boost_ms"),
            field="bonuses.bonus_reflex_boost_ms",
        ),
        bonus_energizer_ms=_require_int(
            _require_field(bonuses, "bonus_energizer_ms", field="bonuses.bonus_energizer_ms"),
            field="bonuses.bonus_energizer_ms",
        ),
        bonus_double_experience_ms=_require_int(
            _require_field(
                bonuses,
                "bonus_double_experience_ms",
                field="bonuses.bonus_double_experience_ms",
            ),
            field="bonuses.bonus_double_experience_ms",
        ),
        bonus_freeze_ms=_require_int(
            _require_field(bonuses, "bonus_freeze_ms", field="bonuses.bonus_freeze_ms"),
            field="bonuses.bonus_freeze_ms",
        ),
    )


def _build_python_trace(replay_path: Path) -> list[TickTrace]:
    replay_bytes = replay_path.read_bytes()
    replay = load_replay(replay_bytes)
    tick_count = len(replay.inputs)
    checkpoint_ticks = set(range(tick_count))
    checkpoints: list[ReplayCheckpoint] = []
    run_survival_replay(
        replay,
        warn_on_version_mismatch=False,
        strict_events=False,
        checkpoints_out=checkpoints,
        checkpoint_ticks=checkpoint_ticks,
    )
    checkpoints.sort(key=lambda checkpoint: int(checkpoint.tick_index))
    return [_checkpoint_to_trace(checkpoint) for checkpoint in checkpoints]


def _load_trace_jsonl(trace_path: Path) -> list[TickTrace]:
    trace_rows: list[TickTrace] = []
    with trace_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            payload = json.loads(line)
            trace_rows.append(_payload_to_trace(payload))
    return trace_rows


def _write_trace_jsonl(trace_path: Path, trace_rows: list[TickTrace]) -> None:
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    with trace_path.open("w", encoding="utf-8") as handle:
        for row in trace_rows:
            line = {
                "schema_version": TRACE_SCHEMA_VERSION,
                "tick_index": int(row["tick_index"]),
                "timing": {
                    "elapsed_ms": int(row["elapsed_ms"]),
                },
                "rng": {
                    "rng_state": int(row["rng_state"]),
                },
                "summary": {
                    "score_xp": int(row["score_xp"]),
                    "kills": int(row["kills"]),
                    "creature_count": int(row["creature_count"]),
                    "creature_state_hash": 0,
                    "perk_pending": int(row["perk_pending"]),
                },
                "player": {
                    "player_weapon_id": int(row["player_weapon_id"]),
                    "player_ammo_q4": int(row["player_ammo_q4"]),
                    "player_health_q4": int(row["player_health_q4"]),
                    "player_level": int(row["player_level"]),
                    "player_experience": int(row["player_experience"]),
                },
                "bonuses": {
                    "bonus_weapon_power_up_ms": int(row["bonus_weapon_power_up_ms"]),
                    "bonus_reflex_boost_ms": int(row["bonus_reflex_boost_ms"]),
                    "bonus_energizer_ms": int(row["bonus_energizer_ms"]),
                    "bonus_double_experience_ms": int(row["bonus_double_experience_ms"]),
                    "bonus_freeze_ms": int(row["bonus_freeze_ms"]),
                },
                "projectiles": {
                    "projectile_state_hash": 0,
                },
                "creatures": {
                    "entries": [],
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
            handle.write(json.dumps(line, separators=(",", ":")))
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


def _load_zig_trace(trace_path: Path) -> list[TickTrace]:
    return _load_trace_jsonl(trace_path)


def _first_mismatch(
    expected: list[TickTrace],
    actual: list[TickTrace],
) -> tuple[int, str, int, int] | None:
    limit = min(len(expected), len(actual))
    for index in range(limit):
        expected_row = expected[index]
        actual_row = actual[index]
        if int(expected_row["tick_index"]) != int(actual_row["tick_index"]):
            return index, "tick_index", int(expected_row["tick_index"]), int(actual_row["tick_index"])
        for key, path in TRACE_FIELDS:
            expected_value = int(expected_row[key])
            actual_value = int(actual_row[key])
            if expected_value != actual_value:
                return index, path, expected_value, actual_value
    if len(expected) != len(actual):
        return limit, "trace_length", len(expected), len(actual)
    return None


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
            python_trace = _load_trace_jsonl(args.python_trace_jsonl)
            rebuild_python_trace = False
            print(f"loaded python trace cache: {args.python_trace_jsonl}")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(
                f"python trace cache invalid ({args.python_trace_jsonl}): {exc}; rebuilding",
                file=sys.stderr,
            )

    if rebuild_python_trace:
        try:
            python_trace = _build_python_trace(replay_path)
        except (ReplayCodecError, ReplayRunnerError) as exc:
            print(f"python trace failed: {exc}", file=sys.stderr)
            return 1
        if args.python_trace_jsonl is not None:
            _write_trace_jsonl(args.python_trace_jsonl, python_trace)
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
        zig_trace = _load_zig_trace(zig_trace_path)

    mismatch = _first_mismatch(python_trace, zig_trace)
    if mismatch is None:
        print(f"match: ticks={len(python_trace)}")
        if zig_run.stderr.strip():
            print("zig stderr:")
            print(zig_run.stderr.strip())
        return 0

    tick_index, key, expected_value, actual_value = mismatch
    print(
        "divergence: "
        f"tick={tick_index} field={key} python={expected_value} zig={actual_value} "
        f"(python_ticks={len(python_trace)} zig_ticks={len(zig_trace)} zig_exit={zig_run.returncode})",
    )
    if zig_run.stderr.strip():
        print("zig stderr:")
        print(zig_run.stderr.strip())
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
