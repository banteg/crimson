from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from crimson.dbg.capture_replay import CAPTURE_REPLAY_SUFFIX, load_capture_replay_file
from crimson.dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION
from crimson.dbg.trace import TraceReader, iter_trace_ticks

# Seeds from captures finalized with this run_start source replay our sim's
# setup draws value-for-value; older captures carry the stale session srand
# seed and cannot be replay-aligned.
_ALIGNED_SEED_SOURCE = "rng_state_before_bootstrap"

_MANIFEST_FORMAT_VERSION = 2


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


def import_run(cdt_path: Path, *, fixtures_dir: Path) -> dict:
    capture_path = cdt_path.with_suffix(CAPTURE_REPLAY_SUFFIX)
    if not capture_path.is_file():
        raise RuntimeError(f"missing capture replay sidecar: {capture_path}")
    with TraceReader(cdt_path) as reader:
        meta = reader.meta
        tick_range = reader.meta.tick_range
        decoded_tick_count = sum(1 for _ in reader.iter_ticks())
    if int(decoded_tick_count) != int(tick_range.tick_count):
        raise RuntimeError(
            f"decoded trace tick count does not match metadata for {cdt_path}: "
            f"decoded={int(decoded_tick_count)} metadata={int(tick_range.tick_count)}",
        )
    capture = load_capture_replay_file(capture_path)
    replay_sha256 = hashlib.sha256(capture_path.read_bytes()).hexdigest()
    if str(meta.producer.impl) != "frida_original":
        raise RuntimeError(f"capture trace producer must be frida_original: {cdt_path}")
    if str(meta.producer.impl_version) != str(FRIDA_CAPTURE_FORMAT_VERSION):
        raise RuntimeError(
            f"capture trace must use Frida format {FRIDA_CAPTURE_FORMAT_VERSION}: "
            f"got {meta.producer.impl_version!r} in {cdt_path}",
        )
    if str(meta.source.replay_sha256) != replay_sha256:
        raise RuntimeError(f"trace replay_sha256 does not match sidecar: {cdt_path}")
    run = capture.run
    capture_quest_level = None if run.quest_level is None else run.quest_level.text
    identity_pairs = {
        "tick_rate": (meta.source.tick_rate, int(capture.tick_rate)),
        "seed": (meta.source.seed, int(run.seed)),
        "mode_id": (meta.source.mode_id, int(run.game_mode_id)),
        "player_count": (meta.source.player_count, int(run.player_count)),
        "quest_level": (meta.source.quest_level, capture_quest_level),
    }
    identity_mismatches = [
        f"{field}: trace={trace_value!r} capture={capture_value!r}"
        for field, (trace_value, capture_value) in identity_pairs.items()
        if trace_value != capture_value
    ]
    if identity_mismatches:
        raise RuntimeError(f"trace/capture identity mismatch for {cdt_path}: " + "; ".join(identity_mismatches))
    if (
        int(tick_range.start_tick) != 0
        or int(tick_range.end_tick) != len(capture.ticks) - 1
        or int(tick_range.tick_count) != len(capture.ticks)
    ):
        raise RuntimeError(
            f"trace/capture tick ranges differ for {cdt_path}: "
            f"trace={int(tick_range.start_tick)}..{int(tick_range.end_tick)} "
            f"count={int(tick_range.tick_count)} capture_count={len(capture.ticks)}",
        )
    native_first = _first_rng_draw(cdt_path)
    seed_source = str(meta.source.run_start_seed_source or "")
    if seed_source != _ALIGNED_SEED_SOURCE:
        raise RuntimeError(
            f"capture trace seed source must be {_ALIGNED_SEED_SOURCE!r}: got {seed_source!r} in {cdt_path}",
        )

    fixtures_dir.mkdir(parents=True, exist_ok=True)
    fixture_capture = fixtures_dir / capture_path.name
    fixture_cdt = fixtures_dir / cdt_path.name
    fixture_capture.write_bytes(capture_path.read_bytes())
    fixture_cdt.write_bytes(cdt_path.read_bytes())

    return {
        "name": cdt_path.stem,
        "ccr": fixture_capture.name,
        "cdt": fixture_cdt.name,
        "source_cdt": str(cdt_path),
        "game_mode_id": int(run.game_mode_id),
        "capture_format_version": int(meta.producer.impl_version),
        "trace_format_version": int(meta.trace_format_version),
        "trace_schema_version": int(meta.trace_schema_version),
        "capture_replay_format_version": int(capture.format_version),
        "tick_count": len(capture.ticks),
        "trace_tick_range": {
            "start_tick": int(tick_range.start_tick),
            "end_tick": int(tick_range.end_tick),
            "tick_count": int(tick_range.tick_count),
        },
        "seed": int(run.seed),
        "seed_source": seed_source,
        "seed_aligned": True,
        "native_first_draw": native_first,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Import finalized frida gameplay captures (.cdt/.ccr) into test fixtures",
    )
    p.add_argument("--captures-dir", type=Path, required=True)
    p.add_argument("--fixtures-dir", type=Path, default=Path("tests/fixtures/captures"))
    p.add_argument("--manifest", type=Path, default=None, help="default: <fixtures-dir>/manifest.json")
    args = p.parse_args()

    cdt_paths = sorted(args.captures_dir.glob("gameplay_diff_capture.*.run*.cdt"))
    if not cdt_paths:
        raise SystemExit(f"no capture traces found in {args.captures_dir}")

    cases = []
    for cdt_path in cdt_paths:
        case = import_run(
            cdt_path,
            fixtures_dir=args.fixtures_dir,
        )
        cases.append(case)
        tick_range = case["trace_tick_range"]
        print(
            f"{case['name']}: seed {case['seed']} ({case['seed_source'] or 'unknown'}, "
            f"aligned={case['seed_aligned']}), ticks "
            f"{tick_range['start_tick']}..{tick_range['end_tick']} ({tick_range['tick_count']})",
        )

    manifest_path = args.manifest or (args.fixtures_dir / "manifest.json")
    manifest_path.write_text(
        json.dumps({"format_version": _MANIFEST_FORMAT_VERSION, "cases": cases}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
