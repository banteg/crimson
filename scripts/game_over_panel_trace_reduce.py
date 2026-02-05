#!/usr/bin/env python3
"""
Reduce game_over_panel_trace.jsonl into a compact summary.

Defaults follow existing Frida tooling paths:
  input:  artifacts/frida/share/game_over_panel_trace.jsonl
  output: analysis/frida/game_over_panel_trace_summary.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


@dataclass
class BBoxStats:
    left_min: float | None = None
    left_max: float | None = None
    top_min: float | None = None
    top_max: float | None = None
    right_min: float | None = None
    right_max: float | None = None
    bottom_min: float | None = None
    bottom_max: float | None = None
    width_min: float | None = None
    width_max: float | None = None
    height_min: float | None = None
    height_max: float | None = None
    samples: int = 0

    def update(self, bbox: list[float] | tuple[float, float, float, float] | None) -> None:
        if not bbox or len(bbox) != 4:
            return
        x0, y0, x1, y1 = [float(v) for v in bbox]
        w = x1 - x0
        h = y1 - y0
        self.samples += 1
        self.left_min = x0 if self.left_min is None else min(self.left_min, x0)
        self.left_max = x0 if self.left_max is None else max(self.left_max, x0)
        self.top_min = y0 if self.top_min is None else min(self.top_min, y0)
        self.top_max = y0 if self.top_max is None else max(self.top_max, y0)
        self.right_min = x1 if self.right_min is None else min(self.right_min, x1)
        self.right_max = x1 if self.right_max is None else max(self.right_max, x1)
        self.bottom_min = y1 if self.bottom_min is None else min(self.bottom_min, y1)
        self.bottom_max = y1 if self.bottom_max is None else max(self.bottom_max, y1)
        self.width_min = w if self.width_min is None else min(self.width_min, w)
        self.width_max = w if self.width_max is None else max(self.width_max, w)
        self.height_min = h if self.height_min is None else min(self.height_min, h)
        self.height_max = h if self.height_max is None else max(self.height_max, h)

    def to_json(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "left": {"min": self.left_min, "max": self.left_max},
            "top": {"min": self.top_min, "max": self.top_max},
            "right": {"min": self.right_min, "max": self.right_max},
            "bottom": {"min": self.bottom_min, "max": self.bottom_max},
            "width": {"min": self.width_min, "max": self.width_max},
            "height": {"min": self.height_min, "max": self.height_max},
        }


def _panel_payload(obj: dict[str, Any]) -> dict[str, Any] | None:
    panel = obj.get("panel")
    return panel if isinstance(panel, dict) else None


def _timeline(obj: dict[str, Any]) -> int:
    state = obj.get("state")
    if not isinstance(state, dict):
        return -1
    ui = state.get("ui")
    if not isinstance(ui, dict):
        return -1
    tl = ui.get("timeline")
    if isinstance(tl, bool):
        return int(tl)
    if isinstance(tl, int):
        return tl
    if isinstance(tl, float):
        return int(tl)
    return -1


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce game-over panel trace JSONL.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("artifacts/frida/share/game_over_panel_trace.jsonl"),
        help="Input JSONL log",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/game_over_panel_trace_summary.json"),
        help="Output summary JSON",
    )
    args = parser.parse_args()

    in_path: Path = args.log
    out_path: Path = args.out

    counts = Counter()
    run_ids: set[str] = set()
    first_ts: str | None = None
    last_ts: str | None = None
    states = Counter()
    phases = Counter()
    resolutions = Counter()
    render_modes = Counter()
    quad_modes = Counter()
    quad_sizes = Counter()
    panel_bbox_stats = BBoxStats()

    # Keep one best sample per ui_screen_phase at max timeline.
    phase_best: dict[int, dict[str, Any]] = {}

    with in_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                counts["json_error"] += 1
                continue

            evt = obj.get("event")
            counts[str(evt)] += 1

            ts = obj.get("ts")
            if isinstance(ts, str):
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

            run_id = obj.get("run_id")
            if isinstance(run_id, str):
                run_ids.add(run_id)

            state = obj.get("state")
            if isinstance(state, dict):
                game = state.get("game")
                if isinstance(game, dict):
                    st = game.get("state_id")
                    if isinstance(st, (int, float)) and not isinstance(st, bool):
                        states[int(st)] += 1
                ui = state.get("ui")
                if isinstance(ui, dict):
                    ph = ui.get("phase")
                    if isinstance(ph, (int, float)) and not isinstance(ph, bool):
                        phases[int(ph)] += 1
                res = state.get("res")
                if isinstance(res, dict):
                    w = res.get("w")
                    h = res.get("h")
                    if isinstance(w, int) and isinstance(h, int):
                        resolutions[f"{w}x{h}"] += 1

            if evt == "textured_quad":
                tex = obj.get("texture_handle")
                w = obj.get("w")
                h = obj.get("h")
                if isinstance(tex, int) and isinstance(w, int) and isinstance(h, int):
                    quad_sizes[f"tex_{tex}:{w}x{h}"] += 1
                continue

            if evt not in ("game_over_begin", "game_over_end", "init"):
                continue

            panel = _panel_payload(obj)
            if panel is None:
                continue

            render_mode = panel.get("render_mode")
            if isinstance(render_mode, int):
                render_modes[render_mode] += 1
            quad_mode = panel.get("quad_mode")
            if isinstance(quad_mode, int):
                quad_modes[quad_mode] += 1

            union_bbox = panel.get("union_bbox_world")
            if isinstance(union_bbox, list) and len(union_bbox) == 4:
                panel_bbox_stats.update([float(v) for v in union_bbox])

            state = obj.get("state")
            phase = None
            if isinstance(state, dict):
                ui = state.get("ui")
                if isinstance(ui, dict):
                    ph = ui.get("phase")
                    if isinstance(ph, (int, float)) and not isinstance(ph, bool):
                        phase = int(ph)

            if phase is None:
                continue
            tl = _timeline(obj)
            cur = phase_best.get(phase)
            if cur is None or tl > int(cur.get("timeline", -1)):
                phase_best[phase] = {
                    "timeline": tl,
                    "event": evt,
                    "seq": obj.get("seq"),
                    "state": state,
                    "panel": panel,
                }

    summary = {
        "generated_at": _now_iso(),
        "source": {
            "path": str(in_path),
            "size_bytes": in_path.stat().st_size if in_path.exists() else None,
        },
        "run_ids": sorted(run_ids),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "event_counts": dict(counts),
        "states": dict(states),
        "ui_phases": dict(phases),
        "resolutions": dict(resolutions),
        "panel": {
            "render_modes": dict(render_modes),
            "quad_modes": dict(quad_modes),
            "bbox_world": panel_bbox_stats.to_json(),
            "best_by_phase": {str(k): v for k, v in sorted(phase_best.items(), key=lambda kv: kv[0])},
        },
        "textured_quad_sizes": dict(quad_sizes),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
