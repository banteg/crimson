from __future__ import annotations

import argparse
import json
from pathlib import Path

import msgspec

from crimson.dbg.schema import TickRecord, TraceTickRange
from crimson.dbg.trace import TraceError, TraceReader, iter_trace_ticks, write_trace_iter
from crimson.replay.codec import ReplayCodecError, load_replay_file
from grim.rand import CRT_RAND_INC, CRT_RAND_MULT

# Seeds from captures finalized with this run_start source replay our sim's
# setup draws value-for-value; older captures carry the stale session srand
# seed and cannot be replay-aligned.
_ALIGNED_SEED_SOURCE = "run_setup_rng_state"

_OUTSIDE_GAP_MAX_DRAWS = 8
_OUTSIDE_GAP_SAMPLE_TICKS = 64


def _first_rng_draw(trace_path: Path) -> dict[str, int] | None:
    for tick in iter_trace_ticks(trace_path):
        rows = tick.channels.rng_stream
        if rows:
            row = rows[0]
            return {
                "tick_index": int(tick.tick_index),
                "state_before_u32": int(row.state_before_u32),
                "value_15": int(row.value_15),
                "caller": int(row.caller) if row.caller is not None else -1,
            }
    return None


def _lcg_distance(state_from: int, state_to: int, *, max_draws: int) -> int | None:
    state = int(state_from)
    for draws in range(int(max_draws) + 1):
        if state == int(state_to):
            return draws
        state = (state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
    return None


def _outside_draws_per_tick(trace_path: Path) -> int | None:
    """Rand draws native burns between consecutive ticks' hooked gameplay
    streams (the discarded per-frame `crt_rand()` in `game_frame_update`).
    None when the gap is absent or inconsistent (e.g. uncapped render fps)."""

    gaps: set[int] = set()
    prev: tuple[int, int] | None = None
    sampled = 0
    for tick in iter_trace_ticks(trace_path):
        rows = tick.channels.rng_stream
        if not rows:
            continue
        if prev is not None and int(tick.tick_index) == prev[0] + 1:
            gap = _lcg_distance(prev[1], int(rows[0].state_before_u32), max_draws=_OUTSIDE_GAP_MAX_DRAWS)
            if gap is None:
                return None
            gaps.add(gap)
            sampled += 1
            if sampled >= _OUTSIDE_GAP_SAMPLE_TICKS:
                break
        prev = (int(tick.tick_index), int(rows[-1].state_after_u32))
    if len(gaps) != 1:
        return None
    return gaps.pop()


def _spaced_windows(
    total_ticks: int,
    *,
    window_ticks: int,
    window_count: int,
    head_end_tick: int,
) -> list[tuple[int, int]]:
    """Inclusive (start, end) tick windows: the head plus evenly spaced samples
    across the rest of the run, with the last window anchored at the tail.
    Overlapping windows are merged."""

    last_tick = int(total_ticks) - 1
    head_end = min(max(int(head_end_tick), int(window_ticks) - 1), last_tick)
    windows = [(0, head_end)]
    extra = max(int(window_count) - 1, 0)
    if extra > 0:
        last_start = max(int(total_ticks) - int(window_ticks), 0)
        for i in range(1, extra + 1):
            start = round(i * last_start / extra)
            windows.append((start, min(start + int(window_ticks) - 1, last_tick)))

    windows.sort()
    merged = [windows[0]]
    for start, end in windows[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _write_windowed_trace(src: Path, dst: Path, *, windows: list[tuple[int, int]]) -> int:
    with TraceReader(src) as reader:
        meta = reader.meta
    ticks: list[TickRecord] = [
        tick
        for tick in iter_trace_ticks(src, tick_start=windows[0][0], tick_end=windows[-1][1])
        if any(start <= int(tick.tick_index) <= end for start, end in windows)
    ]
    trimmed_meta = msgspec.structs.replace(
        meta,
        tick_range=TraceTickRange(
            start_tick=int(ticks[0].tick_index),
            end_tick=int(ticks[-1].tick_index),
            tick_count=len(ticks),
        ),
    )
    write_trace_iter(dst, meta=trimmed_meta, ticks=iter(ticks))
    return len(ticks)


def import_run(cdt_path: Path, *, fixtures_dir: Path, window_ticks: int, window_count: int) -> dict:
    crd_path = cdt_path.with_suffix(".crd")
    if not crd_path.is_file():
        raise RuntimeError(f"missing replay sidecar: {crd_path}")
    with TraceReader(cdt_path) as reader:
        meta = reader.meta
    replay = load_replay_file(crd_path)
    native_first = _first_rng_draw(cdt_path)
    outside_draws_per_tick = _outside_draws_per_tick(cdt_path)

    head_end_tick = int(window_ticks) - 1
    if native_first is not None:
        head_end_tick = max(head_end_tick, native_first["tick_index"] + 7)
    windows = _spaced_windows(
        len(replay.ticks),
        window_ticks=int(window_ticks),
        window_count=int(window_count),
        head_end_tick=head_end_tick,
    )

    fixtures_dir.mkdir(parents=True, exist_ok=True)
    fixture_crd = fixtures_dir / crd_path.name
    fixture_cdt = fixtures_dir / cdt_path.name
    fixture_crd.write_bytes(crd_path.read_bytes())
    kept_count = _write_windowed_trace(cdt_path, fixture_cdt, windows=windows)

    seed_source = str(meta.source.run_start_seed_source or "")
    return {
        "name": cdt_path.stem,
        "crd": fixture_crd.name,
        "cdt": fixture_cdt.name,
        "source_cdt": str(cdt_path),
        "game_mode_id": int(replay.header.game_mode_id),
        "tick_count": len(replay.ticks),
        "windows": [
            {"start_tick": start, "end_tick": end, "tick_count": end - start + 1}
            for start, end in windows
        ],
        "window_tick_count": kept_count,
        "seed": int(replay.header.seed),
        "seed_source": seed_source,
        "seed_aligned": seed_source == _ALIGNED_SEED_SOURCE,
        "native_first_draw": native_first,
        "outside_draws_per_tick": outside_draws_per_tick,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import finalized frida gameplay captures (.cdt/.crd) into test fixtures",
    )
    p.add_argument("--captures-dir", type=Path, required=True)
    p.add_argument("--fixtures-dir", type=Path, default=Path("tests/fixtures/captures"))
    p.add_argument("--manifest", type=Path, default=None, help="default: <fixtures-dir>/manifest.json")
    p.add_argument("--window-ticks", type=int, default=64, help="native trace ticks kept per window")
    p.add_argument("--window-count", type=int, default=4, help="windows spaced across each run (head included)")
    args = p.parse_args()

    cdt_paths = sorted(args.captures_dir.glob("gameplay_diff_capture.*.run*.cdt"))
    if not cdt_paths:
        raise SystemExit(f"no capture traces found in {args.captures_dir}")

    cases = []
    for cdt_path in cdt_paths:
        try:
            with TraceReader(cdt_path):
                pass
        except (TraceError, msgspec.ValidationError) as exc:
            print(f"skipping {cdt_path.name}: not readable with the current trace schema ({exc})")
            continue
        try:
            load_replay_file(cdt_path.with_suffix(".crd"))
        except ReplayCodecError as exc:
            print(f"skipping {cdt_path.name}: replay sidecar not loadable ({exc})")
            continue
        case = import_run(
            cdt_path,
            fixtures_dir=args.fixtures_dir,
            window_ticks=args.window_ticks,
            window_count=args.window_count,
        )
        cases.append(case)
        windows = ", ".join(f"{w['start_tick']}..{w['end_tick']}" for w in case["windows"])
        print(
            f"{case['name']}: seed {case['seed']} ({case['seed_source'] or 'unknown'}, "
            f"aligned={case['seed_aligned']}), windows [{windows}] ({case['window_tick_count']} ticks), "
            f"outside draws/tick {case['outside_draws_per_tick']}",
        )

    manifest_path = args.manifest or (args.fixtures_dir / "manifest.json")
    manifest_path.write_text(json.dumps({"cases": cases}, indent=2) + "\n", encoding="utf-8")
    print(f"manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
