from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Iterator


@dataclass(frozen=True)
class Quad:
    x: float
    y: float
    w: float
    h: float


@dataclass(frozen=True)
class Draw:
    ts: int
    seq: int
    uv_index: int | None
    rotation: float | None
    quad: Quad | None
    player_index: int | None
    thread: int | None


@dataclass
class Call:
    draws: dict[int, Draw]

    @property
    def mode(self) -> int:
        return 4 if 3 in self.draws else 2

    def draw(self, seq: int) -> Draw | None:
        return self.draws.get(seq)


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def parse_quad(obj: Any) -> Quad | None:
    if not isinstance(obj, dict):
        return None
    try:
        return Quad(
            x=float(obj["x"]),
            y=float(obj["y"]),
            w=float(obj["w"]),
            h=float(obj["h"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def parse_draw(obj: dict[str, Any]) -> Draw | None:
    if obj.get("tag") != "draw":
        return None
    try:
        ts = int(obj["ts"])
        seq = int(obj["seq"])
    except (KeyError, TypeError, ValueError):
        return None
    uv_index = obj.get("uv_index")
    if uv_index is not None:
        try:
            uv_index = int(uv_index)
        except (TypeError, ValueError):
            uv_index = None
    rotation = obj.get("rotation")
    if rotation is not None:
        try:
            rotation = float(rotation)
        except (TypeError, ValueError):
            rotation = None
    return Draw(
        ts=ts,
        seq=seq,
        uv_index=uv_index,
        rotation=rotation,
        quad=parse_quad(obj.get("quad")),
        player_index=obj.get("player_index"),
        thread=obj.get("thread"),
    )


def group_calls(draws: Iterable[Draw]) -> list[Call]:
    calls: list[Call] = []
    current: dict[int, Draw] | None = None
    for draw in draws:
        if draw.seq == 1:
            if current:
                calls.append(Call(draws=current))
            current = {}
        if current is None:
            current = {}
        current[draw.seq] = draw
    if current:
        calls.append(Call(draws=current))
    return calls


def quad_delta(a: Quad, b: Quad) -> dict[str, float]:
    # a - b
    return {
        "dx": a.x - b.x,
        "dy": a.y - b.y,
        "dw": a.w - b.w,
        "dh": a.h - b.h,
    }


def summarize_quad_deltas(deltas: list[dict[str, float]]) -> dict[str, Any]:
    if not deltas:
        return {"count": 0}
    fields = ("dx", "dy", "dw", "dh")
    out: dict[str, Any] = {"count": len(deltas)}
    for field in fields:
        values = [d[field] for d in deltas]
        out[field] = {
            "mean": mean(values),
            "min": min(values),
            "max": max(values),
        }
        out[field]["modes"] = Counter(round(v, 3) for v in values).most_common(5)
    return out


def run_length_encode(values: list[int]) -> list[dict[str, int]]:
    if not values:
        return []
    runs: list[dict[str, int]] = []
    current = values[0]
    count = 1
    for value in values[1:]:
        if value == current:
            count += 1
            continue
        runs.append({"uv_index": current, "count": count})
        current = value
        count = 1
    runs.append({"uv_index": current, "count": count})
    return runs


def mode_segments(calls: list[Call]) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for call in calls:
        ts = call.draw(1).ts if call.draw(1) else None
        mode = call.mode
        if current is None or current["mode"] != mode:
            if current is not None:
                segments.append(current)
            current = {"mode": mode, "call_count": 0, "ts_start": ts, "ts_end": ts}
        current["call_count"] += 1
        if ts is not None:
            current["ts_end"] = ts
    if current is not None:
        segments.append(current)
    return segments


def summarize(log_path: Path) -> dict[str, Any]:
    tag_counts: Counter[str] = Counter()
    texture_handles: Counter[int] = Counter()
    session: dict[str, Any] = {}
    parsed_draws: list[Draw] = []

    for obj in iter_jsonl(log_path):
        tag = obj.get("tag")
        if isinstance(tag, str):
            tag_counts[tag] += 1
        if tag == "start":
            session = {
                "exe_base": obj.get("exe_base"),
                "grim_base": obj.get("grim_base"),
                "out_path": obj.get("out_path"),
                "ts": obj.get("ts"),
            }
        elif tag == "texture_handle":
            handle = obj.get("handle")
            if isinstance(handle, int):
                texture_handles[handle] += 1
        elif tag == "draw":
            draw = parse_draw(obj)
            if draw:
                parsed_draws.append(draw)

    calls = group_calls(parsed_draws)

    calls_4 = [c for c in calls if c.mode == 4]
    calls_2 = [c for c in calls if c.mode == 2]

    def ts_range(items: list[Call]) -> tuple[int | None, int | None]:
        ts_values = [c.draw(1).ts for c in items if c.draw(1)]
        if not ts_values:
            return None, None
        return min(ts_values), max(ts_values)

    uv_base = Counter()
    uv_overlay = Counter()
    rot_base = Counter()
    rot_overlay = Counter()
    quad_main_sizes = Counter()
    quad_base_shadow_deltas: list[dict[str, float]] = []
    quad_overlay_shadow_deltas: list[dict[str, float]] = []

    uv_dead = Counter()
    rot_dead = Counter()
    quad_dead_shadow_deltas: list[dict[str, float]] = []
    dead_uv_sequence: list[int] = []

    # 4-draw (alive) pattern
    for call in calls_4:
        d1 = call.draw(1)
        d2 = call.draw(2)
        d3 = call.draw(3)
        d4 = call.draw(4)
        if not (d1 and d2 and d3 and d4):
            continue
        if d1.uv_index is not None:
            uv_base[d1.uv_index] += 1
        if d2.uv_index is not None:
            uv_overlay[d2.uv_index] += 1
        if d1.rotation is not None:
            rot_base[round(d1.rotation, 3)] += 1
        if d2.rotation is not None:
            rot_overlay[round(d2.rotation, 3)] += 1
        if d3.quad is not None:
            quad_main_sizes[round(d3.quad.w, 3)] += 1
        if d1.quad is not None and d3.quad is not None:
            quad_base_shadow_deltas.append(quad_delta(d1.quad, d3.quad))
        if d2.quad is not None and d4.quad is not None:
            quad_overlay_shadow_deltas.append(quad_delta(d2.quad, d4.quad))

    # 2-draw (dead) pattern
    for call in calls_2:
        d1 = call.draw(1)
        d2 = call.draw(2)
        if not (d1 and d2):
            continue
        if d1.uv_index is not None:
            uv_dead[d1.uv_index] += 1
            dead_uv_sequence.append(d1.uv_index)
        if d1.rotation is not None:
            rot_dead[round(d1.rotation, 3)] += 1
        if d1.quad is not None and d2.quad is not None:
            quad_dead_shadow_deltas.append(quad_delta(d1.quad, d2.quad))

    # Relationship checks
    overlay_delta = Counter()
    uv_overlay_bad: list[dict[str, Any]] = []
    for call in calls_4:
        d1 = call.draw(1)
        d2 = call.draw(2)
        if not (d1 and d2 and d1.uv_index is not None and d2.uv_index is not None):
            continue
        overlay_delta[d2.uv_index - d1.uv_index] += 1
        if d2.uv_index - d1.uv_index != 16 and len(uv_overlay_bad) < 5:
            uv_overlay_bad.append({"uv_base": d1.uv_index, "uv_overlay": d2.uv_index})

    dead_runs = run_length_encode(dead_uv_sequence)
    dead_increments = Counter()
    for prev, nxt in zip(dead_runs, dead_runs[1:]):
        dead_increments[nxt["uv_index"] - prev["uv_index"]] += 1

    summary: dict[str, Any] = {
        "events": sum(tag_counts.values()),
        "tags": dict(tag_counts),
        "session": session,
        "script": "scripts/frida/player_sprite_trace.js",
        "source_log": str(session.get("out_path") or log_path),
        "calls": {
            "total": len(calls),
            "mode_segments": mode_segments(calls),
            "alive_4draw": {
                "calls": len(calls_4),
                "ts_start": ts_range(calls_4)[0],
                "ts_end": ts_range(calls_4)[1],
                "uv_base": uv_base.most_common(),
                "uv_overlay": uv_overlay.most_common(),
                "uv_overlay_delta": overlay_delta.most_common(),
                "uv_overlay_delta_bad_examples": uv_overlay_bad,
                "quad_main_size_w": quad_main_sizes.most_common(10),
                "quad_base_shadow_minus_main": summarize_quad_deltas(quad_base_shadow_deltas),
                "quad_overlay_shadow_minus_main": summarize_quad_deltas(quad_overlay_shadow_deltas),
                "rotation_base_top": rot_base.most_common(10),
                "rotation_overlay_top": rot_overlay.most_common(10),
            },
            "dead_2draw": {
                "calls": len(calls_2),
                "ts_start": ts_range(calls_2)[0],
                "ts_end": ts_range(calls_2)[1],
                "uv": uv_dead.most_common(),
                "uv_runs": dead_runs,
                "uv_run_increments": dead_increments.most_common(),
                "rotation_top": rot_dead.most_common(10),
                "quad_shadow_minus_main": summarize_quad_deltas(quad_dead_shadow_deltas),
            },
        },
        "texture_handles": texture_handles.most_common(),
        "notes": [
            "4-draw calls: two sprite layers per call (seq 1/3 and 2/4), where seq 1/2 are shadow/outline passes and seq 3/4 are main passes.",
            "Observed invariant: seq3 repeats seq1 UV index; seq4 repeats seq2 UV index; overlay UV index is base+16 (effect_uv8 offset 0x10).",
            "2-draw calls: single sprite layer with shadow+main; UV runs monotonically from 32..52 then holds at 52 (matches death_timer->ftol index with 0x34 fallback).",
        ],
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize player_sprite_trace JSONL logs.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("analysis/frida/raw/player_sprite_trace.jsonl"),
        help="player_sprite_trace.jsonl path",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/player_sprite_trace_summary.json"),
        help="output summary JSON path",
    )
    args = parser.parse_args()

    summary = summarize(args.log)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
