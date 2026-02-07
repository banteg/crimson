from __future__ import annotations

import argparse
import gzip
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from crimson.game_modes import GameMode
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.diff import ReplayFieldDiff, checkpoint_field_diffs
from crimson.replay.original_capture import (
    OriginalCaptureSidecar,
    build_original_capture_dt_frame_overrides,
    convert_original_capture_to_checkpoints,
    convert_original_capture_to_replay,
    load_original_capture_sidecar,
)
from crimson.sim.runners import run_rush_replay, run_survival_replay


@dataclass(frozen=True, slots=True)
class Divergence:
    tick_index: int
    kind: str
    field_diffs: tuple[ReplayFieldDiff, ...]
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None


def _int_or(value: object, default: int = -1) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _float_or(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _allow_one_tick_creature_count_lag(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "creature_count" for diff in field_diffs):
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    if expected_tick is None or actual_tick is None:
        return False

    expected_count = int(expected_tick.creature_count)
    actual_count = int(actual_tick.creature_count)
    if expected_count < 0 or actual_count < 0:
        return False
    if abs(expected_count - actual_count) != 1:
        return False

    prev_expected = expected_by_tick.get(int(tick) - 1)
    prev_actual = actual_by_tick.get(int(tick) - 1)
    if (
        prev_expected is not None
        and prev_actual is not None
        and int(prev_expected.creature_count) == actual_count
        and int(prev_actual.creature_count) == int(prev_expected.creature_count)
    ):
        return True

    next_expected = expected_by_tick.get(int(tick) + 1)
    next_actual = actual_by_tick.get(int(tick) + 1)
    if (
        next_expected is not None
        and next_actual is not None
        and int(next_expected.creature_count) == actual_count
        and int(next_actual.creature_count) == int(next_expected.creature_count)
    ):
        return True

    return False


def _iter_jsonl_objects(path: Path):
    open_fn = gzip.open if path.suffix == ".gz" else open
    with open_fn(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _load_raw_tick_debug(path: Path, tick_indices: set[int]) -> dict[int, dict[str, object]]:
    lower = path.name.lower()
    if not (lower.endswith(".jsonl") or lower.endswith(".jsonl.gz")):
        return {}

    out: dict[int, dict[str, object]] = {}
    for obj in _iter_jsonl_objects(path):
        if obj.get("event") != "tick":
            continue
        checkpoint = obj.get("checkpoint")
        ckpt = checkpoint if isinstance(checkpoint, dict) else obj
        tick = _int_or(ckpt.get("tick_index"), _int_or(obj.get("tick_index"), -1))
        if tick not in tick_indices:
            continue

        rng_marks = ckpt.get("rng_marks")
        rng_obj = rng_marks if isinstance(rng_marks, dict) else {}
        debug = ckpt.get("debug")
        debug_obj = debug if isinstance(debug, dict) else {}
        spawn = debug_obj.get("spawn")
        spawn_obj = spawn if isinstance(spawn, dict) else {}
        before_players = debug_obj.get("before_players")
        before_players_obj = before_players if isinstance(before_players, list) else []

        out[int(tick)] = {
            "rng_rand_calls": _int_or(rng_obj.get("rand_calls")),
            "rng_rand_last": rng_obj.get("rand_last"),
            "rng_callers": rng_obj.get("rand_callers") if isinstance(rng_obj.get("rand_callers"), list) else [],
            "spawn_bonus_count": _int_or(spawn_obj.get("event_count_bonus_spawn")),
            "spawn_death_count": _int_or(spawn_obj.get("event_count_death")),
            "spawn_top_bonus_callers": (
                spawn_obj.get("top_bonus_spawn_callers")
                if isinstance(spawn_obj.get("top_bonus_spawn_callers"), list)
                else []
            ),
            "before_player0": before_players_obj[0] if before_players_obj else None,
        }
    return out


def _run_actual_checkpoints(
    capture: OriginalCaptureSidecar,
    *,
    max_ticks: int | None,
    seed: int | None,
    inter_tick_rand_draws: int,
) -> tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], object]:
    expected = convert_original_capture_to_checkpoints(capture).checkpoints
    if max_ticks is not None:
        tick_cap = max(0, int(max_ticks))
        expected = [ckpt for ckpt in expected if int(ckpt.tick_index) < int(tick_cap)]

    replay = convert_original_capture_to_replay(capture, seed=seed)
    dt_frame_overrides = build_original_capture_dt_frame_overrides(
        capture,
        tick_rate=int(replay.header.tick_rate),
    )
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected}
    actual: list[ReplayCheckpoint] = []

    mode = int(replay.header.game_mode_id)
    if mode == int(GameMode.SURVIVAL):
        run_result = run_survival_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=False,
            trace_rng=True,
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
        )
    elif mode == int(GameMode.RUSH):
        run_result = run_rush_replay(
            replay,
            max_ticks=max_ticks,
            trace_rng=True,
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
        )
    else:
        raise ValueError(f"unsupported game mode for original capture verification: {mode}")

    return expected, actual, run_result


def _find_first_divergence(
    expected: list[ReplayCheckpoint],
    actual: list[ReplayCheckpoint],
    *,
    float_abs_tol: float,
    max_field_diffs: int,
) -> Divergence | None:
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}

    for exp in expected:
        tick = int(exp.tick_index)
        act = actual_by_tick.get(tick)
        if act is None:
            return Divergence(
                tick_index=int(tick),
                kind="missing_checkpoint",
                field_diffs=(),
                expected=exp,
                actual=None,
            )

        exp_for_diff = replace(exp, elapsed_ms=-1)
        field_diffs = checkpoint_field_diffs(
            exp_for_diff,
            act,
            include_hash_fields=False,
            include_rng_fields=False,
            normalize_unknown=True,
            unknown_events_wildcard=True,
            max_diffs=max_field_diffs,
            float_abs_tol=float(float_abs_tol),
        )
        if _allow_one_tick_creature_count_lag(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
        ):
            continue
        if field_diffs:
            return Divergence(
                tick_index=int(tick),
                kind="state_mismatch",
                field_diffs=tuple(field_diffs),
                expected=exp,
                actual=act,
            )

    return None


def _primary_rng_after(ckpt: ReplayCheckpoint) -> int:
    marks = ckpt.rng_marks
    for key in ("after_wave_spawns", "after_rush_spawns", "after_world_step"):
        if key in marks:
            return _int_or(marks.get(key))
    return -1


def _build_window_rows(
    *,
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    raw_debug_by_tick: dict[int, dict[str, object]],
    focus_tick: int,
    window: int,
) -> list[dict[str, object]]:
    start = max(0, int(focus_tick) - int(window))
    end = int(focus_tick) + int(window)
    rows: list[dict[str, object]] = []
    for tick in range(start, end + 1):
        exp = expected_by_tick.get(tick)
        act = actual_by_tick.get(tick)
        if exp is None or act is None:
            continue
        raw = raw_debug_by_tick.get(int(tick), {})
        exp_player = exp.players[0] if exp.players else None
        act_player = act.players[0] if act.players else None
        before = _int_or(act.rng_marks.get("before_world_step"))
        after = _primary_rng_after(act)

        rows.append(
            {
                "tick": int(tick),
                "expected_weapon": _int_or(getattr(exp_player, "weapon_id", -1)),
                "actual_weapon": _int_or(getattr(act_player, "weapon_id", -1)),
                "expected_ammo": _float_or(getattr(exp_player, "ammo", 0.0)),
                "actual_ammo": _float_or(getattr(act_player, "ammo", 0.0)),
                "expected_xp": _int_or(getattr(exp_player, "experience", -1)),
                "actual_xp": _int_or(getattr(act_player, "experience", -1)),
                "expected_score": int(exp.score_xp),
                "actual_score": int(act.score_xp),
                "expected_creatures": int(exp.creature_count),
                "actual_creatures": int(act.creature_count),
                "expected_rand_calls": _int_or(raw.get("rng_rand_calls"), _int_or(exp.rng_marks.get("rand_calls"))),
                "actual_ps_draws": _int_or(act.rng_marks.get("ps_draws_total")),
                "actual_rng_changed": bool(before >= 0 and after >= 0 and before != after),
                "expected_pickups": int(exp.events.pickup_count),
                "actual_pickups": int(act.events.pickup_count),
                "expected_sfx": int(exp.events.sfx_count),
                "actual_sfx": int(act.events.sfx_count),
                "capture_bonus_spawn_events": _int_or(raw.get("spawn_bonus_count")),
                "capture_death_events": _int_or(raw.get("spawn_death_count")),
            }
        )
    return rows


def _print_window(rows: list[dict[str, object]]) -> None:
    print()
    print(
        "tick  w(e/a)   ammo(e/a)  xp(e/a)   score(e/a)  creatures(e/a)"
        "  rand_calls(e)  ps_draws(a)  rng_changed(a)  bonus_spawn(e)  pickups(e/a)  sfx(e/a)"
    )
    for row in rows:
        print(
            f"{int(row['tick']):4d}  "
            f"{int(row['expected_weapon']):2d}/{int(row['actual_weapon']):2d}    "
            f"{float(row['expected_ammo']):6.2f}/{float(row['actual_ammo']):6.2f}  "
            f"{int(row['expected_xp']):5d}/{int(row['actual_xp']):5d}  "
            f"{int(row['expected_score']):6d}/{int(row['actual_score']):6d}  "
            f"{int(row['expected_creatures']):4d}/{int(row['actual_creatures']):4d}    "
            f"{int(row['expected_rand_calls']):6d}      "
            f"{int(row['actual_ps_draws']):6d}        "
            f"{'Y' if bool(row['actual_rng_changed']) else 'N':>1}           "
            f"{int(row['capture_bonus_spawn_events']):4d}       "
            f"{int(row['expected_pickups']):3d}/{int(row['actual_pickups']):3d}      "
            f"{int(row['expected_sfx']):3d}/{int(row['actual_sfx']):3d}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report the next original-capture divergence with context window + RNG diagnostics.",
    )
    parser.add_argument(
        "capture",
        type=Path,
        help="original capture sidecar (.json/.json.gz) or raw gameplay trace (.jsonl/.jsonl.gz)",
    )
    parser.add_argument("--window", type=int, default=20, help="ticks before/after focus tick to display")
    parser.add_argument("--max-ticks", type=int, default=None, help="optional replay tick cap")
    parser.add_argument("--seed", type=int, default=None, help="optional fixed replay seed override")
    parser.add_argument("--float-abs-tol", type=float, default=1e-3, help="absolute float tolerance")
    parser.add_argument("--max-field-diffs", type=int, default=16, help="max field diffs to show")
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="extra rand draws between ticks (native console loop parity)",
    )
    parser.add_argument(
        "--focus-tick",
        type=int,
        default=None,
        help="override focus tick (default: first mismatch tick)",
    )
    parser.add_argument("--json-out", type=Path, default=None, help="optional machine-readable report output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    capture_path = Path(args.capture)

    capture = load_original_capture_sidecar(capture_path)
    expected, actual, run_result = _run_actual_checkpoints(
        capture,
        max_ticks=args.max_ticks,
        seed=args.seed,
        inter_tick_rand_draws=args.inter_tick_rand_draws,
    )
    divergence = _find_first_divergence(
        expected,
        actual,
        float_abs_tol=float(args.float_abs_tol),
        max_field_diffs=max(1, int(args.max_field_diffs)),
    )

    print(f"capture={capture_path}")
    print(
        f"ticks(expected/actual)={len(expected)}/{len(actual)}"
        f" sample_rate={int(capture.sample_rate)} run_ticks={int(run_result.ticks)}"
        f" run_score_xp={int(run_result.score_xp)} run_kills={int(run_result.creature_kill_count)}"
    )

    replay = convert_original_capture_to_replay(capture, seed=args.seed)
    print(
        f"mode={int(replay.header.game_mode_id)} tick_rate={int(replay.header.tick_rate)}"
        f" player_count={int(replay.header.player_count)} seed={int(replay.header.seed)}"
    )
    print(
        "status="
        f"(quest_unlock_index={int(replay.header.status.quest_unlock_index)}, "
        f"quest_unlock_index_full={int(replay.header.status.quest_unlock_index_full)}, "
        f"weapon_usage_counts_len={len(replay.header.status.weapon_usage_counts)})"
    )

    if divergence is None:
        print("result=ok (no divergence found with current settings)")
        return 0

    focus_tick = int(args.focus_tick) if args.focus_tick is not None else int(divergence.tick_index)
    print()
    print(f"result=diverged kind={divergence.kind} tick={int(divergence.tick_index)} focus_tick={focus_tick}")
    if divergence.field_diffs:
        print("field_diffs:")
        for diff in divergence.field_diffs:
            print(f"  - {diff.field}: expected={diff.expected!r} actual={diff.actual!r}")

    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    window_ticks = set(range(max(0, focus_tick - int(args.window)), focus_tick + int(args.window) + 1))
    raw_debug_by_tick = _load_raw_tick_debug(capture_path, window_ticks | {focus_tick})
    rows = _build_window_rows(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_by_tick,
        focus_tick=focus_tick,
        window=int(args.window),
    )
    _print_window(rows)

    focus_raw = raw_debug_by_tick.get(focus_tick, {})
    if focus_raw:
        print()
        print("focus_capture_debug:")
        print(
            "  "
            f"spawn_bonus_events={_int_or(focus_raw.get('spawn_bonus_count'))} "
            f"spawn_death_events={_int_or(focus_raw.get('spawn_death_count'))} "
            f"rand_calls={_int_or(focus_raw.get('rng_rand_calls'))} "
            f"rand_last={focus_raw.get('rng_rand_last')!r}"
        )
        callers = focus_raw.get("rng_callers")
        if isinstance(callers, list) and callers:
            print(f"  capture_rand_callers_top={callers[:6]!r}")
        top_bonus = focus_raw.get("spawn_top_bonus_callers")
        if isinstance(top_bonus, list) and top_bonus:
            print(f"  capture_bonus_spawn_callers_top={top_bonus[:6]!r}")
        before_player = focus_raw.get("before_player0")
        if isinstance(before_player, dict):
            print(f"  before_player0={before_player!r}")

    zero_rand_consumed = [
        row
        for row in rows
        if int(row["expected_rand_calls"]) == 0 and bool(row["actual_rng_changed"])
    ]
    if zero_rand_consumed:
        print()
        print(
            "hint: expected rand_calls=0 but actual RNG state changed on ticks: "
            + ", ".join(str(int(row["tick"])) for row in zero_rand_consumed[:12])
        )

    if args.json_out is not None:
        payload = {
            "capture": str(capture_path),
            "summary": {
                "expected_count": len(expected),
                "actual_count": len(actual),
                "sample_rate": int(capture.sample_rate),
                "run_ticks": int(run_result.ticks),
                "run_score_xp": int(run_result.score_xp),
                "run_kills": int(run_result.creature_kill_count),
            },
            "replay_header": {
                "game_mode_id": int(replay.header.game_mode_id),
                "tick_rate": int(replay.header.tick_rate),
                "player_count": int(replay.header.player_count),
                "seed": int(replay.header.seed),
                "status": asdict(replay.header.status),
            },
            "divergence": {
                "kind": divergence.kind,
                "tick_index": int(divergence.tick_index),
                "focus_tick": int(focus_tick),
                "field_diffs": [asdict(diff) for diff in divergence.field_diffs],
            },
            "window_rows": rows,
            "focus_capture_debug": focus_raw,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print()
        print(f"json_report={args.json_out}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
