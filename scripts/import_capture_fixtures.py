from __future__ import annotations

import argparse
import json
from pathlib import Path

import msgspec

from crimson.dbg.schema import TickRecord, TraceTickRange
from crimson.dbg.trace import TraceError, TraceReader, iter_trace_ticks, write_trace_iter
from crimson.replay.codec import load_replay_file

# Seeds from captures finalized with this run_start source replay our sim's
# setup draws value-for-value; older captures carry the stale session srand
# seed and cannot be replay-aligned.
_ALIGNED_SEED_SOURCE = "run_setup_rng_state"


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


def _write_trimmed_trace(src: Path, dst: Path, *, window_ticks: int) -> int:
    with TraceReader(src) as reader:
        meta = reader.meta
    ticks: list[TickRecord] = list(iter_trace_ticks(src, tick_start=0, tick_end=window_ticks - 1))
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


def import_run(cdt_path: Path, *, fixtures_dir: Path, window_ticks: int) -> dict:
    crd_path = cdt_path.with_suffix(".crd")
    if not crd_path.is_file():
        raise RuntimeError(f"missing replay sidecar: {crd_path}")
    with TraceReader(cdt_path) as reader:
        meta = reader.meta
    replay = load_replay_file(crd_path)
    native_first = _first_rng_draw(cdt_path)

    window = int(window_ticks)
    if native_first is not None:
        window = max(window, native_first["tick_index"] + 8)
    window = min(window, len(replay.ticks))

    fixtures_dir.mkdir(parents=True, exist_ok=True)
    fixture_crd = fixtures_dir / crd_path.name
    fixture_cdt = fixtures_dir / cdt_path.name
    fixture_crd.write_bytes(crd_path.read_bytes())
    trimmed_count = _write_trimmed_trace(cdt_path, fixture_cdt, window_ticks=window)

    seed_source = str(meta.source.run_start_seed_source or "")
    return {
        "name": cdt_path.stem,
        "crd": fixture_crd.name,
        "cdt": fixture_cdt.name,
        "source_cdt": str(cdt_path),
        "game_mode_id": int(replay.header.game_mode_id),
        "tick_count": len(replay.ticks),
        "window_ticks": trimmed_count,
        "seed": int(replay.header.seed),
        "seed_source": seed_source,
        "seed_aligned": seed_source == _ALIGNED_SEED_SOURCE,
        "native_first_draw": native_first,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import finalized frida gameplay captures (.cdt/.crd) into test fixtures",
    )
    p.add_argument("--captures-dir", type=Path, required=True)
    p.add_argument("--fixtures-dir", type=Path, default=Path("tests/fixtures/captures"))
    p.add_argument("--manifest", type=Path, default=None, help="default: <fixtures-dir>/manifest.json")
    p.add_argument("--window-ticks", type=int, default=64, help="native trace ticks kept per fixture")
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
        case = import_run(cdt_path, fixtures_dir=args.fixtures_dir, window_ticks=args.window_ticks)
        cases.append(case)
        print(
            f"{case['name']}: seed {case['seed']} ({case['seed_source'] or 'unknown'}, "
            f"aligned={case['seed_aligned']}), window {case['window_ticks']} ticks",
        )

    manifest_path = args.manifest or (args.fixtures_dir / "manifest.json")
    manifest_path.write_text(json.dumps({"cases": cases}, indent=2) + "\n", encoding="utf-8")
    print(f"manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
