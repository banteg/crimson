from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from math import inf
from pathlib import Path
from typing import Any, Iterable


@dataclass
class RunningStats:
    count: int = 0
    sum: float = 0.0
    sum_abs: float = 0.0
    min: float = inf
    max: float = -inf

    def add(self, value: float) -> None:
        v = float(value)
        self.count += 1
        self.sum += v
        self.sum_abs += abs(v)
        if v < self.min:
            self.min = v
        if v > self.max:
            self.max = v

    def as_dict(self) -> dict[str, Any]:
        if self.count <= 0:
            return {"count": 0}
        return {
            "count": self.count,
            "mean": self.sum / self.count,
            "mean_abs": self.sum_abs / self.count,
            "min": self.min,
            "max": self.max,
        }


def iter_jsonl(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
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


def _get_float(obj: dict[str, Any], *keys: str) -> float | None:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    if cur is None:
        return None
    if isinstance(cur, (int, float)):
        return float(cur)
    return None


def _get_int(obj: dict[str, Any], *keys: str) -> int | None:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    if cur is None:
        return None
    if isinstance(cur, bool):
        return int(cur)
    if isinstance(cur, int):
        return int(cur)
    if isinstance(cur, float):
        return int(cur)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce creature_anim_trace.jsonl into summary stats.")
    parser.add_argument("--log", action="append", required=True, help="Path to creature_anim_trace.jsonl (repeatable)")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    logs = [Path(p) for p in args.log]
    out_path = Path(args.out)

    events_total = 0
    events_anim = 0
    events_with_delta = 0
    events_with_pred = 0
    session: dict[str, Any] | None = None

    overall_err = RunningStats()
    overall_err_no_local = RunningStats()
    overall_ratio = RunningStats()

    by_type: dict[int, dict[str, RunningStats]] = defaultdict(lambda: {"error": RunningStats(), "error_no_local": RunningStats()})
    by_ai: dict[int, dict[str, RunningStats]] = defaultdict(lambda: {"error": RunningStats(), "error_no_local": RunningStats()})
    by_mode: dict[str, dict[str, RunningStats]] = defaultdict(lambda: {"error": RunningStats(), "error_no_local": RunningStats()})

    for obj in iter_jsonl(logs):
        events_total += 1
        if obj.get("event") == "start" and session is None:
            session = obj
            continue
        if obj.get("event") != "creature_anim":
            continue

        events_anim += 1
        type_id = _get_int(obj, "creature", "type_id_i32")
        ai_mode = _get_int(obj, "creature", "ai_mode_i32")
        long_strip = obj.get("derived", {}).get("long_strip")
        mode_key = "long" if long_strip else "short"

        delta = _get_float(obj, "derived", "delta_phase")
        pred = _get_float(obj, "derived", "step_pred")

        if delta is not None:
            events_with_delta += 1
        if pred is not None:
            events_with_pred += 1

        if delta is None or pred is None:
            continue

        err = delta - pred
        overall_err.add(err)
        if type_id is not None:
            by_type[type_id]["error"].add(err)
        if ai_mode is not None:
            by_ai[ai_mode]["error"].add(err)
        by_mode[mode_key]["error"].add(err)

        # "No local scale" approximates the rewrite bug where local_70 is ignored (local_scale=1.0).
        # Recompute from raw fields to avoid division-by-zero when local_scale -> 0.
        frame_dt = _get_float(obj, "frame_dt")
        size = _get_float(obj, "creature", "size_f32")
        move_speed = _get_float(obj, "creature", "move_speed_f32")
        anim_rate = _get_float(obj, "type", "anim_rate_f32")
        pred_no_local = None
        if (
            frame_dt is not None
            and size is not None
            and move_speed is not None
            and anim_rate is not None
            and size != 0.0
            and ai_mode is not None
        ):
            if mode_key == "long" and ai_mode == 7:
                pred_no_local = 0.0
            else:
                strip_mul = 25.0 if mode_key == "long" else 22.0
                pred_no_local = anim_rate * move_speed * frame_dt * (30.0 / size) * strip_mul
        if pred_no_local is None:
            pred_no_local = pred
        err_no_local = delta - pred_no_local
        overall_err_no_local.add(err_no_local)
        if type_id is not None:
            by_type[type_id]["error_no_local"].add(err_no_local)
        if ai_mode is not None:
            by_ai[ai_mode]["error_no_local"].add(err_no_local)
        by_mode[mode_key]["error_no_local"].add(err_no_local)

        if abs(pred) > 1e-9:
            overall_ratio.add(delta / pred)

    summary: dict[str, Any] = {
        "logs": [str(p) for p in logs],
        "events_total": events_total,
        "events_creature_anim": events_anim,
        "events_with_delta": events_with_delta,
        "events_with_pred": events_with_pred,
        "overall": {
            "error_pred": overall_err.as_dict(),
            "error_pred_no_local": overall_err_no_local.as_dict(),
            "delta_over_pred_ratio": overall_ratio.as_dict(),
        },
        "by_type_id": {str(k): {kk: vv.as_dict() for kk, vv in v.items()} for k, v in sorted(by_type.items())},
        "by_ai_mode": {str(k): {kk: vv.as_dict() for kk, vv in v.items()} for k, v in sorted(by_ai.items())},
        "by_strip_mode": {k: {kk: vv.as_dict() for kk, vv in v.items()} for k, v in sorted(by_mode.items())},
    }
    if session is not None:
        summary["session"] = {
            "exe_base": session.get("exe_base"),
            "logPath": session.get("logPath"),
            "config": session.get("config"),
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
