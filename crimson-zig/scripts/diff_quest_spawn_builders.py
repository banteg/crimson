#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from crimson.quests import all_quests
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext, QuestDefinition, SpawnEntry

FLOAT_EPSILON = 1e-6
DYNAMIC_LEVEL_KEYS = {103, 106, 205, 303, 309}


@dataclass(frozen=True)
class QuestCase:
    impl: str
    level_key: int
    level_label: str
    player_count: int
    seed: int


@dataclass(frozen=True)
class Mismatch:
    case: QuestCase
    reason: str


@dataclass(frozen=True)
class ZigEntry:
    x: float
    y: float
    heading: float
    spawn_id: int
    trigger_ms: int
    count: int


@dataclass(frozen=True)
class ZigBuildResult:
    start_weapon_id: int
    entries: tuple[ZigEntry, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diff Zig quest spawn builder modules vs Python builders.")
    parser.add_argument(
        "--impl",
        action="append",
        default=[],
        help="Zig implementation id (legacy|option4|option6). Repeat for multiple impls.",
    )
    parser.add_argument(
        "--dynamic-seed",
        action="append",
        type=int,
        default=[],
        help="Seed to use for dynamic-seed levels (repeatable).",
    )
    parser.add_argument(
        "--static-seed",
        type=int,
        default=205,
        help="Seed to use for seed-invariant quest levels.",
    )
    parser.add_argument(
        "--world-size",
        type=float,
        default=1024.0,
        help="Quest map width/height passed to Zig.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip `zig build` before diffing.",
    )
    parser.add_argument(
        "--optimize",
        default="ReleaseFast",
        help="Optimize mode for `zig build` (Debug|ReleaseSafe|ReleaseFast|ReleaseSmall).",
    )
    parser.add_argument(
        "--max-mismatches",
        type=int,
        default=20,
        help="How many mismatch details to print before truncating.",
    )
    return parser.parse_args()


def _format_level_key(level_key: int) -> str:
    major = level_key // 100
    minor = level_key % 100
    return f"{major}.{minor}"


def _quest_level_key(quest: QuestDefinition) -> int:
    return int(quest.major) * 100 + int(quest.minor)


def _float_equal(left: float, right: float) -> bool:
    return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=FLOAT_EPSILON)


def _parse_zig_entry(raw: object) -> ZigEntry:
    if not isinstance(raw, dict):
        raise TypeError(f"entry is not an object: {raw!r}")
    pos = raw.get("pos")
    if not isinstance(pos, dict):
        raise TypeError(f"entry.pos is not an object: {raw!r}")

    x = pos.get("x")
    y = pos.get("y")
    heading = raw.get("heading")
    spawn_id = raw.get("spawn_id")
    trigger_ms = raw.get("trigger_ms")
    count = raw.get("count")

    if not isinstance(x, (int, float)):
        raise TypeError(f"entry.pos.x is not numeric: {raw!r}")
    if not isinstance(y, (int, float)):
        raise TypeError(f"entry.pos.y is not numeric: {raw!r}")
    if not isinstance(heading, (int, float)):
        raise TypeError(f"entry.heading is not numeric: {raw!r}")
    if not isinstance(spawn_id, int):
        raise TypeError(f"entry.spawn_id is not int: {raw!r}")
    if not isinstance(trigger_ms, int):
        raise TypeError(f"entry.trigger_ms is not int: {raw!r}")
    if not isinstance(count, int):
        raise TypeError(f"entry.count is not int: {raw!r}")

    return ZigEntry(
        x=float(x),
        y=float(y),
        heading=float(heading),
        spawn_id=int(spawn_id),
        trigger_ms=int(trigger_ms),
        count=int(count),
    )


def _parse_zig_result(stdout: str) -> ZigBuildResult:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON from Zig tool: {exc}") from exc
    if not isinstance(payload, dict):
        raise TypeError("top-level JSON is not an object")

    start_weapon_id = payload.get("start_weapon_id")
    entries_raw = payload.get("entries")
    if not isinstance(start_weapon_id, int):
        raise TypeError(f"start_weapon_id is not int: {start_weapon_id!r}")
    if not isinstance(entries_raw, list):
        raise TypeError("entries is not a list")

    entries = tuple(_parse_zig_entry(entry) for entry in entries_raw)
    return ZigBuildResult(start_weapon_id=int(start_weapon_id), entries=entries)


def _run_zig_tool(
    tool_path: Path,
    *,
    impl: str,
    level_key: int,
    player_count: int,
    seed: int,
    world_size: float,
) -> ZigBuildResult:
    proc = subprocess.run(
        [
            str(tool_path),
            impl,
            str(level_key),
            str(player_count),
            str(seed),
            str(world_size),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "zig tool failed "
            f"(impl={impl} level={level_key} players={player_count} seed={seed}): "
            f"{proc.stderr.strip()}",
        )
    return _parse_zig_result(proc.stdout)


def _compare_entries(
    *,
    case: QuestCase,
    expected: tuple[SpawnEntry, ...],
    actual: tuple[ZigEntry, ...],
) -> Mismatch | None:
    if len(expected) != len(actual):
        return Mismatch(
            case=case,
            reason=f"entry length mismatch expected={len(expected)} actual={len(actual)}",
        )

    for idx, (exp, act) in enumerate(zip(expected, actual, strict=True)):
        if not _float_equal(float(exp.pos.x), act.x):
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].pos.x mismatch expected={float(exp.pos.x)!r} actual={act.x!r}",
            )
        if not _float_equal(float(exp.pos.y), act.y):
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].pos.y mismatch expected={float(exp.pos.y)!r} actual={act.y!r}",
            )
        if not _float_equal(float(exp.heading), act.heading):
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].heading mismatch expected={float(exp.heading)!r} actual={act.heading!r}",
            )
        if int(exp.spawn_id) != act.spawn_id:
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].spawn_id mismatch expected={int(exp.spawn_id)} actual={act.spawn_id}",
            )
        if int(exp.trigger_ms) != act.trigger_ms:
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].trigger_ms mismatch expected={int(exp.trigger_ms)} actual={act.trigger_ms}",
            )
        if int(exp.count) != act.count:
            return Mismatch(
                case=case,
                reason=f"entry[{idx}].count mismatch expected={int(exp.count)} actual={act.count}",
            )
    return None


def _build_if_needed(crimson_zig_dir: Path, *, optimize: str, skip_build: bool) -> None:
    if skip_build:
        return
    zig_bin = shutil.which("zig")
    if zig_bin is None:
        raise FileNotFoundError("zig executable not found in PATH")
    subprocess.run(
        [zig_bin, "build", f"-Doptimize={optimize}"],
        cwd=crimson_zig_dir,
        check=True,
    )


def _tool_path(crimson_zig_dir: Path) -> Path:
    return crimson_zig_dir / "zig-out" / "bin" / "crimson-zig-quest-spawn-dump"


def _seeds_for_level(level_key: int, *, dynamic_seeds: tuple[int, ...], static_seed: int) -> tuple[int, ...]:
    if level_key in DYNAMIC_LEVEL_KEYS:
        return dynamic_seeds
    return (static_seed,)


def run() -> int:
    args = parse_args()

    impls = tuple(args.impl) if args.impl else ("option4", "option6")
    dynamic_seeds = tuple(args.dynamic_seed) if args.dynamic_seed else (0, 1, 205, 999)
    if not dynamic_seeds:
        raise ValueError("dynamic seed list cannot be empty")

    repo_root = Path(__file__).resolve().parents[2]
    crimson_zig_dir = repo_root / "crimson-zig"

    _build_if_needed(crimson_zig_dir, optimize=str(args.optimize), skip_build=bool(args.skip_build))

    tool_path = _tool_path(crimson_zig_dir)
    if not tool_path.exists():
        raise FileNotFoundError(f"quest spawn dump tool not found: {tool_path}")

    mismatches: list[Mismatch] = []
    checked: int = 0

    quests = all_quests()
    for quest in quests:
        level_key = _quest_level_key(quest)
        for player_count in range(1, 5):
            ctx = QuestContext(
                width=int(args.world_size),
                height=int(args.world_size),
                player_count=int(player_count),
            )
            for seed in _seeds_for_level(
                level_key,
                dynamic_seeds=dynamic_seeds,
                static_seed=int(args.static_seed),
            ):
                expected_entries = build_quest_spawn_table(
                    quest,
                    ctx,
                    seed=int(seed),
                    hardcore=False,
                    full_version=True,
                )
                for impl in impls:
                    case = QuestCase(
                        impl=impl,
                        level_key=level_key,
                        level_label=_format_level_key(level_key),
                        player_count=player_count,
                        seed=int(seed),
                    )
                    actual = _run_zig_tool(
                        tool_path,
                        impl=impl,
                        level_key=level_key,
                        player_count=player_count,
                        seed=int(seed),
                        world_size=float(args.world_size),
                    )
                    checked += 1

                    if int(quest.start_weapon_id) != int(actual.start_weapon_id):
                        mismatches.append(
                            Mismatch(
                                case=case,
                                reason=(
                                    "start_weapon_id mismatch "
                                    f"expected={int(quest.start_weapon_id)} actual={int(actual.start_weapon_id)}"
                                ),
                            ),
                        )
                        if len(mismatches) >= int(args.max_mismatches):
                            break
                        continue

                    mismatch = _compare_entries(
                        case=case,
                        expected=expected_entries,
                        actual=actual.entries,
                    )
                    if mismatch is not None:
                        mismatches.append(mismatch)
                        if len(mismatches) >= int(args.max_mismatches):
                            break
                if len(mismatches) >= int(args.max_mismatches):
                    break
            if len(mismatches) >= int(args.max_mismatches):
                break
        if len(mismatches) >= int(args.max_mismatches):
            break

    if mismatches:
        print(
            f"quest builder diff: FAIL checked={checked} mismatches={len(mismatches)} "
            f"(showing up to {args.max_mismatches})",
            file=sys.stderr,
        )
        for mismatch in mismatches:
            case = mismatch.case
            print(
                "  "
                f"impl={case.impl} level={case.level_label}({case.level_key}) "
                f"players={case.player_count} seed={case.seed}: {mismatch.reason}",
                file=sys.stderr,
            )
        return 1

    print(
        f"quest builder diff: OK checked={checked} impls={','.join(impls)} "
        f"dynamic_seeds={list(dynamic_seeds)} static_seed={int(args.static_seed)}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
