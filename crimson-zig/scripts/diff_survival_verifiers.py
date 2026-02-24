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
    tick: int
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


TRACE_KEYS: tuple[str, ...] = (
    "rng_state",
    "elapsed_ms",
    "score_xp",
    "kills",
    "creature_count",
    "perk_pending",
    "player_weapon_id",
    "player_ammo_q4",
    "player_health_q4",
    "player_level",
    "player_experience",
    "bonus_weapon_power_up_ms",
    "bonus_reflex_boost_ms",
    "bonus_energizer_ms",
    "bonus_double_experience_ms",
    "bonus_freeze_ms",
)

BONUS_KEY_WEAPON_POWER_UP = str(BonusId.WEAPON_POWER_UP)
BONUS_KEY_REFLEX_BOOST = str(BonusId.REFLEX_BOOST)
BONUS_KEY_ENERGIZER = str(BonusId.ENERGIZER)
BONUS_KEY_DOUBLE_EXPERIENCE = str(BonusId.DOUBLE_EXPERIENCE)
BONUS_KEY_FREEZE = str(BonusId.FREEZE)


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
        tick=int(checkpoint.tick_index),
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


def _build_python_trace(replay_path: Path) -> list[TickTrace]:
    replay_bytes = replay_path.read_bytes()
    replay = load_replay(replay_bytes)
    tick_count = len(replay.inputs)
    checkpoint_ticks = set(range(tick_count))
    checkpoints: list[ReplayCheckpoint] = []
    run_survival_replay(
        replay,
        warn_on_version_mismatch=False,
        strict_events=True,
        checkpoints_out=checkpoints,
        checkpoint_ticks=checkpoint_ticks,
    )
    checkpoints.sort(key=lambda checkpoint: int(checkpoint.tick_index))
    return [_checkpoint_to_trace(checkpoint) for checkpoint in checkpoints]


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
    trace_rows: list[TickTrace] = []
    with trace_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            payload = json.loads(line)
            row = TickTrace(
                tick=int(payload["tick"]),
                rng_state=int(payload["rng_state"]),
                elapsed_ms=int(payload["elapsed_ms"]),
                score_xp=int(payload["score_xp"]),
                kills=int(payload["kills"]),
                creature_count=int(payload["creature_count"]),
                perk_pending=int(payload["perk_pending"]),
                player_weapon_id=int(payload["player_weapon_id"]),
                player_ammo_q4=int(payload["player_ammo_q4"]),
                player_health_q4=int(payload["player_health_q4"]),
                player_level=int(payload["player_level"]),
                player_experience=int(payload["player_experience"]),
                bonus_weapon_power_up_ms=int(payload["bonus_weapon_power_up_ms"]),
                bonus_reflex_boost_ms=int(payload["bonus_reflex_boost_ms"]),
                bonus_energizer_ms=int(payload["bonus_energizer_ms"]),
                bonus_double_experience_ms=int(payload["bonus_double_experience_ms"]),
                bonus_freeze_ms=int(payload["bonus_freeze_ms"]),
            )
            trace_rows.append(row)
    return trace_rows


def _first_mismatch(
    expected: list[TickTrace],
    actual: list[TickTrace],
) -> tuple[int, str, int, int] | None:
    limit = min(len(expected), len(actual))
    for index in range(limit):
        expected_row = expected[index]
        actual_row = actual[index]
        if int(expected_row["tick"]) != int(actual_row["tick"]):
            return index, "tick", int(expected_row["tick"]), int(actual_row["tick"])
        for key in TRACE_KEYS:
            expected_value = int(expected_row[key])
            actual_value = int(actual_row[key])
            if expected_value != actual_value:
                return index, str(key), expected_value, actual_value
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

    try:
        python_trace = _build_python_trace(replay_path)
    except (ReplayCodecError, ReplayRunnerError) as exc:
        print(f"python trace failed: {exc}", file=sys.stderr)
        return 1

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
