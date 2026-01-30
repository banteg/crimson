from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


@dataclass(frozen=True, slots=True)
class FadePoint:
    line: int
    ts: int
    tag: str
    mode_name: str | None
    fade_alpha: float
    fade_ramp: int
    game_state_pending: int | None
    game_state_id: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "ts": self.ts,
            "tag": self.tag,
            "mode_name": self.mode_name,
            "fade_alpha": self.fade_alpha,
            "fade_ramp": self.fade_ramp,
            "game_state_pending": self.game_state_pending,
            "game_state_id": self.game_state_id,
        }


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield idx, obj


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return int(value)
    return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _extract_fade_point(line: int, obj: dict[str, Any]) -> FadePoint | None:
    snapshot = obj.get("snapshot")
    if not isinstance(snapshot, dict):
        return None
    ts = _as_int(obj.get("ts"))
    if ts is None:
        return None
    fade_alpha = _as_float(snapshot.get("fade_alpha"))
    fade_ramp = _as_int(snapshot.get("fade_ramp"))
    if fade_alpha is None or fade_ramp is None:
        return None
    tag = obj.get("tag")
    tag_str = tag if isinstance(tag, str) else "unknown"
    return FadePoint(
        line=line,
        ts=ts,
        tag=tag_str,
        mode_name=obj.get("mode_name") if isinstance(obj.get("mode_name"), str) else None,
        fade_alpha=fade_alpha,
        fade_ramp=int(fade_ramp),
        game_state_pending=_as_int(snapshot.get("game_state_pending")),
        game_state_id=_as_int(snapshot.get("game_state_id")),
    )


def summarize(log_path: Path, *, eps: float = 1e-3) -> dict[str, Any]:
    tag_counts: Counter[str] = Counter()
    points: list[FadePoint] = []
    last_summary: dict[str, Any] | None = None

    for line, obj in iter_jsonl(log_path):
        tag = obj.get("tag")
        tag_str = tag if isinstance(tag, str) else "unknown"
        tag_counts[tag_str] += 1
        if tag_str == "summary":
            last_summary = obj
        point = _extract_fade_point(line, obj)
        if point is not None:
            points.append(point)

    transitions: list[dict[str, Any]] = []
    prev: FadePoint | None = None
    for point in points:
        if prev is None:
            prev = point
            continue
        if point.fade_ramp == prev.fade_ramp:
            prev = point
            continue

        direction = "up" if point.fade_ramp == 1 else "down"
        start = point
        threshold = 1.0 - eps if direction == "up" else eps

        end: FadePoint | None = None
        for candidate in points:
            if candidate.ts < start.ts:
                continue
            if candidate.fade_ramp != start.fade_ramp:
                break
            if direction == "up":
                if candidate.fade_alpha >= threshold:
                    end = candidate
                    break
            else:
                if candidate.fade_alpha <= threshold:
                    end = candidate
                    break

        duration_ms = (end.ts - start.ts) if end is not None else None
        transitions.append(
            {
                "direction": direction,
                "start": start.as_dict(),
                "end": end.as_dict() if end is not None else None,
                "duration_ms": duration_ms,
            }
        )
        prev = point

    def _durations(direction: str) -> list[int]:
        values: list[int] = []
        for entry in transitions:
            if entry.get("direction") != direction:
                continue
            duration = entry.get("duration_ms")
            if isinstance(duration, int):
                values.append(duration)
        return values

    def _stats(values: list[int]) -> dict[str, Any]:
        if not values:
            return {"count": 0}
        return {
            "count": len(values),
            "min_ms": min(values),
            "max_ms": max(values),
            "mean_ms": sum(values) / len(values),
        }

    return {
        "script": "scripts/frida/screen_fade_trace.js",
        "source_log": "analysis\\frida\\raw\\screen_fade_trace.jsonl",
        "tag_counts": dict(tag_counts),
        "snapshot_events": len(points),
        "fade_ramp_transitions": transitions,
        "stats": {
            "fade_to_black": _stats(_durations("up")),
            "fade_from_black": _stats(_durations("down")),
        },
        "trace_summary": {
            "counts": last_summary.get("counts") if isinstance(last_summary, dict) else None,
            "base_exe": last_summary.get("base_exe") if isinstance(last_summary, dict) else None,
            "base_grim": last_summary.get("base_grim") if isinstance(last_summary, dict) else None,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce screen_fade_trace JSONL logs into a small summary JSON.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("analysis/frida/raw/screen_fade_trace.jsonl"),
        help="screen_fade_trace.jsonl path",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/screen_fade_trace_summary.json"),
        help="output summary JSON path",
    )
    args = parser.parse_args()

    summary = summarize(args.log)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
