#!/usr/bin/env python3
"""
Reduce ui_render_trace.jsonl into small, reviewable artifacts.

This log can be very large (hundreds of MB), so this reducer is strictly
streaming and only keeps bounded state in memory.

Outputs:
  - <out_dir>/ui_render_trace_summary.json
  - <out_dir>/ui_render_trace_marked_frames.jsonl

The marked-frames JSONL stores one record per auto_mark event with the most
recently completed ui_frame snapshot (draw calls + element/widget scopes).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def _now_iso() -> str:
    # Avoid importing datetime in hot paths; only used for metadata.
    import datetime as _dt

    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _is_probably_font_texture(texture0: int | None, texture_name: str | None) -> bool:
    # In our captures the default font atlas is texture handle 6 (GRIM_Font2).
    # Keep this heuristic very small: it is only used to filter noisy per-glyph
    # quads when a higher-level grim_draw_text event exists.
    if texture0 == 6:
        return True
    if not texture_name:
        return False
    return texture_name.startswith("GRIM_Font")


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
    We truncate at the first non-ASCII char to avoid huge garbage tails.
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
    # Normalize whitespace.
    title = " ".join(title.split())
    if len(title) > 160:
        title = title[:160]
    return title


def _is_world_texture(texture_name: str | None) -> bool:
    if not texture_name:
        return False
    # Keep this conservative; we only want to drop egregious background noise.
    return texture_name.startswith("ter\\")


def _apply_transform(x: float, y: float, offset: tuple[float, float], matrix: tuple[float, float, float, float] | None) -> tuple[float, float]:
    if matrix is None:
        return (x + offset[0], y + offset[1])
    m00, m01, m10, m11 = matrix
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


def _norm_element_ref(el: Any) -> dict[str, Any] | None:
    if not isinstance(el, dict):
        return None
    out = {"ptr": el.get("ptr"), "index": el.get("index")}
    snap = el.get("snapshot")
    if isinstance(snap, dict):
        out["snapshot"] = snap
    return out


def _norm_draw_event(obj: dict[str, Any]) -> dict[str, Any] | None:
    evt = obj.get("event")
    if evt is None:
        return None

    # Skip ultra-noisy per-glyph quads; we keep the higher-level grim_draw_text events.
    ds = _norm_draw_state(obj.get("draw_state"))
    if evt == "grim_draw_quad" and ds and _is_probably_font_texture(ds.get("texture0"), ds.get("texture0_name")):
        return None
    if evt in ("grim_draw_quad", "grim_draw_quad_xy") and ds and _is_world_texture(ds.get("texture0_name")):
        return None

    base: dict[str, Any] = {
      "event": evt,
      "scope": obj.get("scope"),
        "element": _norm_element_ref(obj.get("element")),
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
            vtx_out: list[dict[str, Any]] = []
            for v in verts:
                if not isinstance(v, dict):
                    continue
                x = v.get("x")
                y = v.get("y")
                if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                    continue
                xs, ys = _apply_transform(float(x), float(y), off, mat)
                points.append((xs, ys))
                vtx_out.append(
                    {
                        "x": xs,
                        "y": ys,
                        "uv": v.get("uv"),
                        "color": (v.get("color") or {}).get("u32") if isinstance(v.get("color"), dict) else None,
                    }
                )
            base.update(
                {
                    "kind": obj.get("kind"),
                    "count": obj.get("count"),
                    "offset": [off[0], off[1]],
                    "matrix": None if mat is None else [mat[0], mat[1], mat[2], mat[3]],
                    "verts_screen": vtx_out,
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
            base.update({"xy": [x0, y0], "w": float(w), "h": float(h), "bbox": _bbox(pts)})
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
            base.update({"x": x0, "y": y0, "w": float(w), "h": float(h), "bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_quad_xy":
        xy = obj.get("xy")
        w = obj.get("w")
        h = obj.get("h")
        if isinstance(xy, list) and len(xy) == 2 and isinstance(w, (int, float)) and isinstance(h, (int, float)):
            x0, y0 = float(xy[0]), float(xy[1])
            x1, y1 = x0 + float(w), y0 + float(h)
            pts = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
            base.update({"xy": [x0, y0], "w": float(w), "h": float(h), "bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_quad_points":
        pts_raw = [obj.get("p0"), obj.get("p1"), obj.get("p2"), obj.get("p3")]
        pts: list[tuple[float, float]] = []
        for p in pts_raw:
            if isinstance(p, list) and len(p) == 2 and all(isinstance(v, (int, float)) for v in p):
                pts.append((float(p[0]), float(p[1])))
        if len(pts) == 4:
            base.update({"points": [[x, y] for x, y in pts], "bbox": _bbox(pts)})
        return base

    if evt == "grim_draw_text":
        txt = obj.get("text")
        base.update(
            {
                "font": obj.get("font"),
                "x": obj.get("x"),
                "y": obj.get("y"),
                "text": txt,
                "text_clean": clean_title(txt),
            }
        )
        return base

    if evt == "scope_begin":
        # Preserve widget inputs to make state reconstruction possible.
        scope = obj.get("scope")
        payload = obj.get("payload")
        base.update({"scope": scope, "payload": payload})
        return base

    if evt == "ui_element_begin":
        base.update({"element": _norm_element_ref(obj.get("element"))})
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

    def to_json(self) -> dict[str, Any]:
        return {
            "tid": self.tid,
            "ui_frame": self.ui_frame,
            "begin_seq": self.begin_seq,
            "begin_ts": self.begin_ts,
            "end_seq": self.end_seq,
            "end_ts": self.end_ts,
            "state": self.state,
            "events": self.events,
        }


def main() -> int:
    p = argparse.ArgumentParser(description="Reduce ui_render_trace.jsonl into summaries.")
    p.add_argument("--log", type=Path, default=Path("artifacts/frida/share/ui_render_trace.jsonl"))
    p.add_argument("--out-dir", type=Path, default=Path("analysis/frida"))
    p.add_argument("--max-frame-events", type=int, default=20000, help="Safety cap to avoid runaway memory per frame.")
    args = p.parse_args()

    in_path: Path = args.log
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    out_frames_path = out_dir / "ui_render_trace_marked_frames.jsonl"
    out_summary_path = out_dir / "ui_render_trace_summary.json"

    counts = Counter()
    run_ids: set[str] = set()
    first_ts: str | None = None
    last_ts: str | None = None
    init_event: dict[str, Any] | None = None

    # Track per-thread UI frames.
    frames_in_progress: dict[int, Frame] = {}
    last_ended_frame: Frame | None = None

    # Track basic auto_mark stats.
    auto_mark_seen = 0
    auto_mark_states = Counter()
    resolutions = Counter()

    # Track a best-effort texture handle -> cleaned name.
    texture_names: dict[int, str] = {}

    def write_frame_record(out_f, mark_obj: dict[str, Any], frame: Frame | None) -> None:
        record = {
            "auto_mark": mark_obj,
            "frame": frame.to_json() if frame is not None else None,
        }
        out_f.write(json.dumps(record, ensure_ascii=True) + "\n")

    with in_path.open("r", encoding="utf-8", errors="replace") as f_in, out_frames_path.open("w", encoding="utf-8") as f_out:
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

            if evt == "init" and init_event is None:
                init_event = obj

            # Texture name mapping.
            ds = obj.get("draw_state")
            if isinstance(ds, dict):
                h = ds.get("texture0")
                n = ds.get("texture0_name")
                if isinstance(h, int) and h not in texture_names and isinstance(n, str):
                    cn = clean_texture_name(n)
                    if cn:
                        texture_names[h] = cn

            if evt == "grim_bind_texture":
                h = obj.get("handle")
                n = obj.get("name")
                if isinstance(h, int) and h not in texture_names and isinstance(n, str):
                    cn = clean_texture_name(n)
                    if cn:
                        texture_names[h] = cn

            # Frame lifecycle.
            if evt == "ui_frame_begin":
                tid = obj.get("tid")
                ui_frame = obj.get("ui_frame")
                if isinstance(tid, int) and isinstance(ui_frame, int):
                    fr = Frame(tid=tid, ui_frame=ui_frame, begin_seq=obj.get("seq"), begin_ts=ts, state=obj.get("state"))
                    frames_in_progress[tid] = fr
                continue

            if evt == "ui_frame_end":
                tid = obj.get("tid")
                ui_frame = obj.get("ui_frame")
                if isinstance(tid, int) and isinstance(ui_frame, int):
                    fr = frames_in_progress.pop(tid, None)
                    if fr is None:
                        fr = Frame(tid=tid, ui_frame=ui_frame)
                    fr.end_seq = obj.get("seq")
                    fr.end_ts = ts
                    last_ended_frame = fr
                continue

            # auto_mark: attach the most recently ended frame (written right after ui_frame_end in the trace script).
            if evt == "auto_mark":
                auto_mark_seen += 1
                state = obj.get("state") or {}
                st_id = ((state.get("game") or {}).get("state_id"))
                if st_id is not None:
                    auto_mark_states[st_id] += 1
                res = state.get("res") or {}
                if isinstance(res, dict):
                    w = res.get("w")
                    h = res.get("h")
                    if isinstance(w, int) and isinstance(h, int):
                        resolutions[f"{w}x{h}"] += 1

                # Enrich mark with cleaned label/title to keep downstream tools stable.
                mark_obj = dict(obj)
                txts = obj.get("texts") or []
                if isinstance(txts, list) and txts:
                    title = clean_title(txts[0])
                else:
                    title = None
                label = obj.get("label")
                mark_obj["label_clean"] = clean_title(label) or label
                mark_obj["title_clean"] = title

                # Add best-effort frame hint to the mark.
                if last_ended_frame is not None:
                    mark_obj["ui_frame_hint"] = {"tid": last_ended_frame.tid, "ui_frame": last_ended_frame.ui_frame}
                else:
                    mark_obj["ui_frame_hint"] = None

                write_frame_record(f_out, mark_obj, last_ended_frame)
                last_ended_frame = None
                continue

            # Collect draw events inside an active frame (by tid).
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
                # Frame is too noisy (likely due to text glyph quads if our filter missed).
                # Keep the earliest events (they usually include the panel setup) and drop the rest.
                fr.events = fr.events[: args.max_frame_events]

    summary = {
        "generated_at": _now_iso(),
        "source": {"path": str(in_path), "size_bytes": in_path.stat().st_size if in_path.exists() else None},
        "run_ids": sorted(run_ids),
        "init": init_event,
        "event_counts": dict(counts),
        "auto_mark_count": auto_mark_seen,
        "auto_mark_states": dict(auto_mark_states),
        "resolutions": dict(resolutions),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "texture_names": texture_names,
        "outputs": {"marked_frames": str(out_frames_path), "summary": str(out_summary_path)},
    }

    out_summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Wrote {out_summary_path}")
    print(f"Wrote {out_frames_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
