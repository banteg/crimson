#!/usr/bin/env python3
"""
Extract a small, reviewable UI layout "oracle" from ui_render_trace.jsonl.

Goal: take the very large runtime trace and distill it into per-screen snapshots
that are useful for validating our port's UI layout math (initially at 1024x768).

This script is intentionally streaming and keeps bounded state in memory.

Output:
  analysis/frida/ui_render_trace_oracle_1024x768.json (by default)

The oracle stores, per detected screen label:
  - representative (max timeline) frame metadata
  - per-texture draw instances (bbox + UV/sub-rect/atlas/config)
  - captured text draws (x/y + cleaned text)
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def _now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _clean_prefix(s: str | None, allowed: str) -> str | None:
    if not s:
        return None
    out: list[str] = []
    for ch in str(s):
        if ch in allowed:
            out.append(ch)
        else:
            break
    if not out:
        return None
    return "".join(out)


def clean_texture_name(s: str | None) -> str | None:
    # Keep it path-ish.
    return _clean_prefix(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./\\-")


def clean_title(s: str | None) -> str | None:
    """
    Produce a stable, human-readable title from captured draw_text strings.

    The game uses non-ASCII control/color bytes which Frida decodes as U+FFFD.
    We truncate at the first non-ASCII char to avoid garbage tails.
    """

    if not s:
        return None
    s = str(s)
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if ch == "\ufffd":
            break
        if o < 0x20 and ch not in ("\t", " "):
            break
        if o > 0x7E:
            break
        out.append(ch)
    title = "".join(out).strip()
    if not title:
        return None
    title = " ".join(title.split())
    if len(title) > 160:
        title = title[:160]
    return title


def _is_probably_font_texture(texture0: int | None, texture_name: str | None) -> bool:
    # In our captures the default font atlas is texture handle 6 (GRIM_Font2).
    if texture0 == 6:
        return True
    if not texture_name:
        return False
    return texture_name.startswith("GRIM_Font")


def _is_world_texture(texture_name: str | None) -> bool:
    if not texture_name:
        return False
    return texture_name.startswith("ter\\")


def _apply_transform(
    x: float,
    y: float,
    offset: tuple[float, float],
    matrix: tuple[float, float, float, float] | None,
) -> tuple[float, float]:
    if matrix is None:
        return (x + offset[0], y + offset[1])
    m00, m01, m10, m11 = matrix
    # Matrix layout inferred from grim.dll callsites: [m00 m01; m10 m11].
    return (x * m00 + y * m01 + offset[0], x * m10 + y * m11 + offset[1])


def _bbox(points: Iterable[tuple[float, float]]) -> tuple[float, float, float, float] | None:
    it = iter(points)
    try:
        x0, y0 = next(it)
    except StopIteration:
        return None
    min_x = max_x = x0
    min_y = max_y = y0
    for x, y in it:
        if x < min_x:
            min_x = x
        elif x > max_x:
            max_x = x
        if y < min_y:
            min_y = y
        elif y > max_y:
            max_y = y
    return (min_x, min_y, max_x, max_y)


def _norm_draw_state(ds: Any) -> dict[str, Any] | None:
    if not isinstance(ds, dict):
        return None
    t0 = ds.get("texture0")
    t0n = ds.get("texture0_name")
    return {
        "texture0": t0,
        "texture0_name": clean_texture_name(t0n) or None,
        "uv": ds.get("uv"),
        "color": ds.get("color"),
        "rotation": ds.get("rotation"),
        "atlas": ds.get("atlas"),
        "sub_rect": ds.get("sub_rect"),
        "config": ds.get("config"),
    }


def _norm_draw_event(obj: dict[str, Any]) -> dict[str, Any] | None:
    evt = obj.get("event")
    if evt is None:
        return None

    ds = _norm_draw_state(obj.get("draw_state"))
    if evt in ("grim_draw_quad", "grim_draw_quad_xy", "grim_submit_vertices") and ds:
        if _is_world_texture(ds.get("texture0_name")):
            return None
        if evt == "grim_draw_quad" and _is_probably_font_texture(ds.get("texture0"), ds.get("texture0_name")):
            return None

    base: dict[str, Any] = {
        "event": evt,
        "scope": obj.get("scope"),
        "draw_state": ds,
    }

    if evt == "grim_submit_vertices":
        offset = obj.get("offset")
        matrix = obj.get("matrix")
        verts = obj.get("verts")

        if (
            isinstance(offset, list)
            and len(offset) == 2
            and all(isinstance(v, (int, float)) for v in offset)
            and (matrix is None or (isinstance(matrix, list) and len(matrix) == 4 and all(isinstance(v, (int, float)) for v in matrix)))
            and isinstance(verts, list)
        ):
            off = (float(offset[0]), float(offset[1]))
            mat = None if matrix is None else (float(matrix[0]), float(matrix[1]), float(matrix[2]), float(matrix[3]))
            points: list[tuple[float, float]] = []
            for v in verts:
                if not isinstance(v, dict):
                    continue
                x = v.get("x")
                y = v.get("y")
                if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                    continue
                xs, ys = _apply_transform(float(x), float(y), off, mat)
                points.append((xs, ys))
            base.update(
                {
                    "kind": obj.get("kind"),
                    "count": obj.get("count"),
                    "bbox": _bbox(points),
                }
            )
        return base

    if evt in ("grim_draw_rect_filled", "grim_draw_rect_outline"):
        xy = obj.get("xy")
        w = obj.get("w")
        h = obj.get("h")
        if isinstance(xy, list) and len(xy) == 2 and isinstance(w, (int, float)) and isinstance(h, (int, float)):
            x0, y0 = float(xy[0]), float(xy[1])
            x1, y1 = x0 + float(w), y0 + float(h)
            pts = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
            base.update({"bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_quad":
        x = obj.get("x")
        y = obj.get("y")
        w = obj.get("w")
        h = obj.get("h")
        if all(isinstance(v, (int, float)) for v in (x, y, w, h)):
            x0, y0 = float(x), float(y)
            x1, y1 = x0 + float(w), y0 + float(h)
            pts = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
            base.update({"bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_quad_xy":
        xy = obj.get("xy")
        w = obj.get("w")
        h = obj.get("h")
        if isinstance(xy, list) and len(xy) == 2 and isinstance(w, (int, float)) and isinstance(h, (int, float)):
            x0, y0 = float(xy[0]), float(xy[1])
            x1, y1 = x0 + float(w), y0 + float(h)
            pts = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
            base.update({"bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_quad_points":
        pts_raw = [obj.get("p0"), obj.get("p1"), obj.get("p2"), obj.get("p3")]
        pts: list[tuple[float, float]] = []
        for p in pts_raw:
            if isinstance(p, list) and len(p) == 2 and all(isinstance(v, (int, float)) for v in p):
                pts.append((float(p[0]), float(p[1])))
        if len(pts) == 4:
            base.update({"bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_text":
        txt = obj.get("text")
        base.update(
            {
                "font": obj.get("font"),
                "x": obj.get("x"),
                "y": obj.get("y"),
                "text_clean": clean_title(txt),
            }
        )
        return base

    return None


@dataclass
class Frame:
    tid: int
    ui_frame: int
    begin_seq: int | None = None
    begin_ts: str | None = None
    end_seq: int | None = None
    end_ts: str | None = None
    state: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)


def _frame_timeline(state: dict[str, Any] | None) -> int:
    if not isinstance(state, dict):
        return -1
    ui = state.get("ui") or {}
    tl = ui.get("timeline")
    if isinstance(tl, bool):
        return int(tl)
    if isinstance(tl, int):
        return int(tl)
    if isinstance(tl, float):
        return int(tl)
    return -1


def _frame_res_key(state: dict[str, Any] | None) -> str | None:
    if not isinstance(state, dict):
        return None
    res = state.get("res") or {}
    if not isinstance(res, dict):
        return None
    w = res.get("w")
    h = res.get("h")
    if isinstance(w, int) and isinstance(h, int):
        return f"{w}x{h}"
    return None


def _frame_state_id(state: dict[str, Any] | None) -> int | None:
    if not isinstance(state, dict):
        return None
    game = state.get("game") or {}
    if not isinstance(game, dict):
        return None
    st = game.get("state_id")
    if isinstance(st, bool):
        return int(st)
    if isinstance(st, int):
        return int(st)
    if isinstance(st, float):
        return int(st)
    return None


def _extract_layout(frame: Frame) -> dict[str, Any]:
    textures: dict[str, dict[str, Any]] = {}
    texts: list[dict[str, Any]] = []
    counts = Counter()

    for e in frame.events:
        evt = e.get("event")
        counts[evt] += 1

        if evt == "grim_draw_text":
            tc = e.get("text_clean")
            x = e.get("x")
            y = e.get("y")
            if tc and isinstance(x, (int, float)) and isinstance(y, (int, float)):
                texts.append({"text": tc, "x": float(x), "y": float(y), "font": e.get("font")})
            continue

        bbox = e.get("bbox")
        if not (isinstance(bbox, (list, tuple)) and len(bbox) == 4):
            continue
        if not all(isinstance(v, (int, float)) for v in bbox):
            continue

        ds = e.get("draw_state") or {}
        if not isinstance(ds, dict):
            continue
        tn = ds.get("texture0_name")
        if not isinstance(tn, str) or not tn:
            continue

        # Preserve per-instance slice/atlas data; it is useful for reconstructing draw modes.
        inst = {
            "event": evt,
            "bbox": [float(bbox[0]), float(bbox[1]), float(bbox[2]), float(bbox[3])],
            "uv": ds.get("uv"),
            "atlas": ds.get("atlas"),
            "sub_rect": ds.get("sub_rect"),
            "config": ds.get("config"),
            "color": ds.get("color"),
        }
        bucket = textures.setdefault(tn, {"instances": [], "count": 0, "union_bbox": None})
        bucket["instances"].append(inst)
        bucket["count"] = int(bucket["count"]) + 1
        ub = bucket["union_bbox"]
        if ub is None:
            bucket["union_bbox"] = inst["bbox"]
        else:
            bucket["union_bbox"] = [
                min(float(ub[0]), float(inst["bbox"][0])),
                min(float(ub[1]), float(inst["bbox"][1])),
                max(float(ub[2]), float(inst["bbox"][2])),
                max(float(ub[3]), float(inst["bbox"][3])),
            ]

    # Keep text order stable (draw order); it helps visually scanning reports.
    return {
        "event_counts": dict(counts),
        "textures": textures,
        "texts": texts,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Extract a small per-screen UI oracle from ui_render_trace.jsonl.")
    p.add_argument("--log", type=Path, default=Path("artifacts/frida/share/ui_render_trace.jsonl"))
    p.add_argument(
        "--out",
        type=Path,
        default=Path("analysis/frida/ui_render_trace_oracle_1024x768.json"),
        help="Output JSON path (small, commit-friendly)",
    )
    p.add_argument("--resolution", type=str, default="1024x768", help="Only keep frames at this resolution (e.g. 1024x768)")
    p.add_argument(
        "--max-frame-events",
        type=int,
        default=40000,
        help="Safety cap to avoid runaway memory for pathological frames (font glyph spam, etc).",
    )
    args = p.parse_args(argv)

    in_path: Path = args.log
    out_path: Path = args.out
    want_res: str | None = args.resolution or None

    counts = Counter()
    first_ts: str | None = None
    last_ts: str | None = None
    run_ids: set[str] = set()

    # Frames currently being captured (per thread).
    frames_in_progress: dict[int, Frame] = {}

    # ui_frame_end events are followed by an optional auto_mark; keep a pending frame
    # so we can attribute the frame to the new label when the mark fires.
    pending_ended: Frame | None = None

    current_label: str | None = None
    current_state_id: int | None = None

    # Per-label stats and best-frame selection (by max UI timeline).
    label_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"frames": 0, "timeline_min": None, "timeline_max": None})
    best_by_label: dict[str, dict[str, Any]] = {}

    def _maybe_adopt_frame(label: str, fr: Frame) -> None:
        st = fr.state
        if want_res is not None and _frame_res_key(st) != want_res:
            return
        tl = _frame_timeline(st)
        s = label_stats[label]
        s["frames"] = int(s["frames"]) + 1
        if s["timeline_min"] is None or tl < int(s["timeline_min"]):
            s["timeline_min"] = tl
        if s["timeline_max"] is None or tl > int(s["timeline_max"]):
            s["timeline_max"] = tl

        cur = best_by_label.get(label)
        if cur is None or tl > int(cur.get("timeline") or -1):
            best_by_label[label] = {
                "label": label,
                "state_id": _frame_state_id(st),
                "resolution": _frame_res_key(st),
                "timeline": tl,
                "frame": {
                    "tid": fr.tid,
                    "ui_frame": fr.ui_frame,
                    "begin_ts": fr.begin_ts,
                    "end_ts": fr.end_ts,
                    "begin_seq": fr.begin_seq,
                    "end_seq": fr.end_seq,
                    "ui": (st or {}).get("ui"),
                    "game": (st or {}).get("game"),
                    "res": (st or {}).get("res"),
                },
                "layout": _extract_layout(fr),
            }

    def _flush_pending_to_current() -> None:
        nonlocal pending_ended
        if pending_ended is None:
            return
        if current_label is not None:
            _maybe_adopt_frame(current_label, pending_ended)
        pending_ended = None

    with in_path.open("r", encoding="utf-8", errors="replace") as f_in:
        for raw_line in f_in:
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                counts["json_error"] += 1
                continue

            evt = obj.get("event")
            counts[evt] += 1

            ts = obj.get("ts")
            if isinstance(ts, str):
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

            run_id = obj.get("run_id")
            if isinstance(run_id, str):
                run_ids.add(run_id)

            if evt == "ui_frame_begin":
                # If the previous frame ended without an auto_mark, attribute it to the
                # current label before we start a new frame.
                _flush_pending_to_current()

                tid = obj.get("tid")
                ui_frame = obj.get("ui_frame")
                if not (isinstance(tid, int) and isinstance(ui_frame, int)):
                    continue
                frames_in_progress[tid] = Frame(
                    tid=tid,
                    ui_frame=ui_frame,
                    begin_seq=obj.get("seq"),
                    begin_ts=ts,
                    state=obj.get("state"),
                )
                continue

            if evt == "ui_frame_end":
                tid = obj.get("tid")
                ui_frame = obj.get("ui_frame")
                if not (isinstance(tid, int) and isinstance(ui_frame, int)):
                    continue
                fr = frames_in_progress.pop(tid, None)
                if fr is None:
                    fr = Frame(tid=tid, ui_frame=ui_frame)
                fr.end_seq = obj.get("seq")
                fr.end_ts = ts
                pending_ended = fr
                continue

            if evt == "auto_mark":
                # Attribute the just-ended frame to this new label (marks are emitted right after ui_frame_end).
                label_raw = obj.get("label")
                label_clean = clean_title(label_raw) or (str(label_raw) if label_raw is not None else None)
                title = None
                txts = obj.get("texts") or []
                if isinstance(txts, list) and txts:
                    title = clean_title(txts[0])
                _ = title  # currently unused; label already includes title when present

                state = obj.get("state") or {}
                st_id = _frame_state_id(state)

                if label_clean:
                    current_label = label_clean
                    current_state_id = st_id
                    if pending_ended is not None:
                        _maybe_adopt_frame(current_label, pending_ended)
                        pending_ended = None
                continue

            # Collect events inside an active frame (by tid).
            tid = obj.get("tid")
            if not isinstance(tid, int):
                continue
            fr = frames_in_progress.get(tid)
            if fr is None:
                continue

            norm = _norm_draw_event(obj)
            if norm is None:
                continue
            fr.events.append(norm)
            if len(fr.events) > args.max_frame_events:
                fr.events = fr.events[: args.max_frame_events]

    # EOF: flush any pending frame.
    _flush_pending_to_current()

    # Stable ordering: state_id then label.
    screens = sorted(
        best_by_label.values(),
        key=lambda s: (
            int(s.get("state_id") or 9999),
            str(s.get("label") or ""),
        ),
    )

    out = {
        "generated_at": _now_iso(),
        "source": {"path": str(in_path), "size_bytes": in_path.stat().st_size if in_path.exists() else None},
        "run_ids": sorted(run_ids),
        "resolution_filter": want_res,
        "event_counts": dict(counts),
        "labels": {k: v for k, v in sorted(label_stats.items(), key=lambda kv: kv[0])},
        "screens": screens,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} ({len(screens)} screens)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

