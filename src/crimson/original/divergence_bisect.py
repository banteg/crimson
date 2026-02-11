from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from crimson.replay.checkpoints import ReplayCheckpoint

from .capture import load_capture
from .divergence_report import (
    Divergence,
    _actual_rng_stream_rows_for_checkpoint,
    _build_window_rows,
    _find_first_divergence,
    _load_capture_sample_creature_counts,
    _load_raw_tick_debug,
    _compute_rng_stream_alignment,
    _run_actual_checkpoints,
    _rng_stream_rows_for_raw_row,
)
from .capture import parse_player_int_overrides

_JSON_OUT_AUTO = "__AUTO__"
_DEFAULT_JSON_OUT_PATH = Path("artifacts/frida/reports/divergence_bisect_latest.json")


def _int_or(value: object, default: int = -1) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)  # ty:ignore[invalid-argument-type]
    except Exception:
        return int(default)


def _resolve_json_out_path(value: str | None) -> Path | None:
    if value is None:
        return None
    if str(value) == _JSON_OUT_AUTO:
        return Path(_DEFAULT_JSON_OUT_PATH)
    return Path(value)


def _binary_search_first_bad_tick(
    *,
    start_tick: int,
    end_tick: int,
    is_bad: Callable[[int], bool],
) -> int | None:
    lo = int(start_tick)
    hi = int(end_tick)
    found: int | None = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if bool(is_bad(int(mid))):
            found = int(mid)
            hi = int(mid) - 1
        else:
            lo = int(mid) + 1
    return found


def _build_repro_tick_row(
    *,
    tick: int,
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    raw: dict[str, object],
    rng_row_limit: int,
    branch_event_limit: int,
) -> dict[str, object]:
    capture_stream_rows = _rng_stream_rows_for_raw_row(raw)
    capture_head_len = _int_or(raw.get("rng_head_len"), len(capture_stream_rows))
    if capture_head_len < 0:
        capture_head_len = len(capture_stream_rows)
    row_limit = max(1, int(rng_row_limit))
    rewrite_stream_rows, rewrite_total_calls = _actual_rng_stream_rows_for_checkpoint(
        actual,
        max_rows=max(int(row_limit), len(capture_stream_rows)),
    )
    stream_alignment = _compute_rng_stream_alignment(
        act=actual,
        capture_stream_rows=capture_stream_rows,
        capture_head_len=int(capture_head_len),
    )

    branch_limit = max(1, int(branch_event_limit))

    def _head(name: str) -> list[object]:
        rows_obj = raw.get(name)
        rows = list(rows_obj) if isinstance(rows_obj, list) else []
        return rows[:branch_limit]

    return {
        "tick": int(tick),
        "expected": {
            "score_xp": int(expected.score_xp),
            "creature_count": int(expected.creature_count),
            "rand_calls": int(expected.rng_marks.get("rand_calls", -1)),
        },
        "actual": {
            "score_xp": int(actual.score_xp),
            "creature_count": int(actual.creature_count),
            "rand_calls": stream_alignment.get("actual_calls"),
            "rand_stage_calls": {
                key: int(value)
                for key, value in sorted(actual.rng_marks.items())
                if str(key).startswith(("ws_", "after_", "before_", "ps_draws"))
            },
        },
        "rng_stream_alignment": stream_alignment,
        "capture_rng_stream_rows": capture_stream_rows[:row_limit],
        "rewrite_rng_stream_rows": rewrite_stream_rows[:row_limit],
        "rewrite_rng_total_calls": rewrite_total_calls,
        "capture_rng_total_calls": _int_or(raw.get("rng_rand_calls"), -1),
        "capture_rng_seq_range": {
            "first": _int_or(raw.get("rng_seq_first"), -1),
            "last": _int_or(raw.get("rng_seq_last"), -1),
        },
        "capture_branch_events": {
            "creature_damage_head": _head("creature_damage_head"),
            "creature_death_head": _head("creature_death_head"),
            "projectile_find_query_head": _head("projectile_find_query_head"),
            "projectile_find_hit_head": _head("projectile_find_hit_head"),
            "projectile_spawn_head": _head("projectile_spawn_head"),
            "secondary_projectile_spawn_head": _head("secondary_projectile_spawn_head"),
            "bonus_spawn_head": _head("bonus_spawn_head"),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Binary-search the earliest divergent tick for an original capture and emit a compact repro bundle "
            "(window rows + RNG stream rows + branch event heads)."
        ),
    )
    parser.add_argument("capture", type=Path, help="capture file (.json/.json.gz)")
    parser.add_argument("--seed", type=int, default=None, help="optional fixed replay seed override")
    parser.add_argument(
        "--aim-scheme-player",
        action="append",
        default=[],
        metavar="PLAYER=SCHEME",
        help=(
            "override replay reconstruction aim scheme for player index "
            "(repeatable; use for captures missing config_aim_scheme telemetry)"
        ),
    )
    parser.add_argument("--max-ticks", type=int, default=None, help="optional replay tick cap for search")
    parser.add_argument("--float-abs-tol", type=float, default=1e-3, help="absolute float tolerance")
    parser.add_argument("--max-field-diffs", type=int, default=16, help="max field diffs to consider")
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="extra rand draws between ticks (native console loop parity)",
    )
    parser.add_argument("--window-before", type=int, default=12, help="ticks before first bad tick in repro bundle")
    parser.add_argument("--window-after", type=int, default=6, help="ticks after first bad tick in repro bundle")
    parser.add_argument("--rng-row-limit", type=int, default=128, help="max RNG rows per tick in repro bundle")
    parser.add_argument("--branch-event-limit", type=int, default=32, help="max branch event rows per kind per tick")
    parser.add_argument(
        "--json-out",
        nargs="?",
        default=None,
        const=_JSON_OUT_AUTO,
        help=(
            "optional JSON output path "
            "(default when flag is present: artifacts/frida/reports/divergence_bisect_latest.json)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    capture_path = Path(args.capture)
    json_out_path = _resolve_json_out_path(args.json_out)
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            args.aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        print(exc)
        return 2

    capture = load_capture(capture_path)
    raw_debug_all = _load_raw_tick_debug(capture_path)
    capture_sample_creature_counts = _load_capture_sample_creature_counts(capture_path)

    expected_ticks = sorted(int(tick.tick_index) for tick in capture.ticks)
    if not expected_ticks:
        print(f"capture={capture_path}")
        print("result=ok (capture has no ticks)")
        return 0

    start_tick = int(expected_ticks[0])
    end_tick = int(expected_ticks[-1])
    if args.max_ticks is not None:
        end_tick = min(int(end_tick), max(0, int(args.max_ticks) - 1))
    if end_tick < start_tick:
        print(f"capture={capture_path}")
        print("result=ok (tick range empty after --max-ticks)")
        return 0

    probe_cache: dict[int, tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], Divergence | None]] = {}
    probes: list[dict[str, object]] = []

    def _run_probe(max_tick: int) -> tuple[list[ReplayCheckpoint], list[ReplayCheckpoint], Divergence | None]:
        key = int(max_tick)
        cached = probe_cache.get(key)
        if cached is not None:
            return cached

        expected, actual, _run_result = _run_actual_checkpoints(
            capture,
            max_ticks=int(key) + 1,
            seed=args.seed,
            inter_tick_rand_draws=int(args.inter_tick_rand_draws),
            aim_scheme_overrides_by_player=aim_scheme_overrides,
        )
        divergence = _find_first_divergence(
            expected,
            actual,
            float_abs_tol=float(args.float_abs_tol),
            max_field_diffs=max(1, int(args.max_field_diffs)),
            capture_sample_creature_counts=capture_sample_creature_counts,
            raw_debug_by_tick=raw_debug_all,
        )
        probes.append(
            {
                "max_tick": int(key),
                "diverged": bool(divergence is not None),
                "divergence_tick": (int(divergence.tick_index) if divergence is not None else None),
                "divergence_kind": (str(divergence.kind) if divergence is not None else None),
            }
        )
        result = (expected, actual, divergence)
        probe_cache[key] = result
        return result

    _expected_end, _actual_end, divergence_end = _run_probe(int(end_tick))
    print(f"capture={capture_path}")
    print(f"search_range={int(start_tick)}..{int(end_tick)}")
    if divergence_end is None:
        print("result=ok (no divergence in search range)")
        if json_out_path is not None:
            payload = {
                "capture": str(capture_path),
                "search_range": {"start_tick": int(start_tick), "end_tick": int(end_tick)},
                "result": "ok",
                "probes": probes,
            }
            json_out_path.parent.mkdir(parents=True, exist_ok=True)
            json_out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"json_report={json_out_path}")
        return 0

    first_bad_tick = _binary_search_first_bad_tick(
        start_tick=int(start_tick),
        end_tick=int(end_tick),
        is_bad=lambda max_tick: _run_probe(int(max_tick))[2] is not None,
    )
    if first_bad_tick is None:
        print("result=error (binary search failed to resolve first bad tick)")
        return 1

    _expected_first, _actual_first, first_divergence = _run_probe(int(first_bad_tick))
    if first_divergence is None:
        print("result=error (binary search probe at first bad tick reported no divergence)")
        return 1

    print(
        f"result=diverged first_bad_tick={int(first_bad_tick)} "
        f"kind={first_divergence.kind} divergence_tick={int(first_divergence.tick_index)}"
    )

    window_before = max(0, int(args.window_before))
    window_after = max(0, int(args.window_after))
    repro_start = max(int(start_tick), int(first_bad_tick) - int(window_before))
    repro_end = min(int(end_tick), int(first_bad_tick) + int(window_after))

    _expected_window, _actual_window, _div_window = _run_probe(int(repro_end))
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in _expected_window}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in _actual_window}

    window_ticks = set(range(int(repro_start), int(repro_end) + 1))
    raw_debug_window = {int(tick): row for tick, row in raw_debug_all.items() if int(tick) in window_ticks}
    window_rows = _build_window_rows(
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        raw_debug_by_tick=raw_debug_window,
        focus_tick=int(first_bad_tick),
        window=max(int(first_bad_tick) - int(repro_start), int(repro_end) - int(first_bad_tick)),
    )

    repro_rows: list[dict[str, object]] = []
    for tick in range(int(repro_start), int(repro_end) + 1):
        expected_ckpt = expected_by_tick.get(int(tick))
        actual_ckpt = actual_by_tick.get(int(tick))
        if expected_ckpt is None or actual_ckpt is None:
            continue
        raw = raw_debug_window.get(int(tick), {})
        repro_rows.append(
            _build_repro_tick_row(
                tick=int(tick),
                expected=expected_ckpt,
                actual=actual_ckpt,
                raw=raw,
                rng_row_limit=max(1, int(args.rng_row_limit)),
                branch_event_limit=max(1, int(args.branch_event_limit)),
            )
        )

    if json_out_path is not None:
        payload = {
            "capture": str(capture_path),
            "search_range": {"start_tick": int(start_tick), "end_tick": int(end_tick)},
            "result": "diverged",
            "first_bad_tick": int(first_bad_tick),
            "divergence": {
                "tick_index": int(first_divergence.tick_index),
                "kind": str(first_divergence.kind),
                "field_diffs": [
                    {"field": str(item.field), "expected": item.expected, "actual": item.actual}
                    for item in first_divergence.field_diffs
                ],
            },
            "repro_window": {
                "start_tick": int(repro_start),
                "end_tick": int(repro_end),
                "window_rows": window_rows,
                "tick_rows": repro_rows,
            },
            "probes": probes,
        }
        json_out_path.parent.mkdir(parents=True, exist_ok=True)
        json_out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"json_report={json_out_path}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
