from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from dataclasses import dataclass
from math import inf
from pathlib import Path
from typing import Any, Iterator


@dataclass
class RunningStats:
    count: int = 0
    sum: float = 0.0
    min: float = inf
    max: float = -inf

    def add(self, value: float) -> None:
        v = float(value)
        self.count += 1
        self.sum += v
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
            "min": self.min,
            "max": self.max,
        }


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


def _get(obj: dict[str, Any], *keys: str) -> Any:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _get_int(obj: dict[str, Any], *keys: str) -> int | None:
    return _as_int(_get(obj, *keys))


def _get_float(obj: dict[str, Any], *keys: str) -> float | None:
    return _as_float(_get(obj, *keys))


def _get_str(obj: dict[str, Any], *keys: str) -> str | None:
    value = _get(obj, *keys)
    return value if isinstance(value, str) else None


def _abs_err(obs: float | None, exp: float | None) -> float | None:
    if obs is None or exp is None:
        return None
    return abs(float(obs) - float(exp))


def _rot_err(obs: float | None, exp: float | None) -> float | None:
    """Smallest absolute angular difference (wrap at 2pi)."""
    if obs is None or exp is None:
        return None
    a = float(obs) - float(exp)
    a = (a + math.pi) % (2.0 * math.pi) - math.pi
    return abs(a)


def _expected_uv(frame: int) -> dict[str, float]:
    frame_i = int(frame) & 0xF
    u0 = (frame_i & 3) * 0.25
    v0 = (frame_i >> 2) * 0.25
    return {"u0": u0, "v0": v0, "u1": u0 + 0.25, "v1": v0 + 0.25}


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce fx_queue_render_trace.jsonl into corpse bake validation stats.")
    parser.add_argument("--log", required=True, help="Path to fx_queue_render_trace.jsonl")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    log_path = Path(args.log)
    out_path = Path(args.out)

    # Session header (from init event)
    session_init: dict[str, Any] | None = None

    fx_render_calls = 0
    fx_render_calls_rotated = 0
    rotated_counts: Counter[int] = Counter()
    bodies_transparency: Counter[str] = Counter()

    # Track only "interesting" calls (rot_count > 0)
    active: dict[int, dict[str, Any]] = {}

    # Validation stats
    batch_order_ok = 0
    batch_order_bad = 0

    blend_shadow: Counter[str] = Counter()
    blend_color: Counter[str] = Counter()

    err_xy = RunningStats()
    err_wh = RunningStats()
    err_rot = RunningStats()
    err_alpha = RunningStats()
    err_uv = RunningStats()

    mismatches: list[dict[str, Any]] = []

    eps_xy = 2e-3
    eps_rot = 2e-4
    eps_uv = 2e-6
    eps_alpha = 2e-4

    for obj in iter_jsonl(log_path):
        event = obj.get("event")
        if event == "init" and session_init is None:
            session_init = obj
            continue

        if event == "fx_queue_render_enter":
            fx_render_calls += 1
            fx_call = _get_int(obj, "fx_call")
            snapshot = _get(obj, "snapshot")
            rot_count = _as_int(snapshot.get("rot_count")) if isinstance(snapshot, dict) else None
            bodies = _as_float(snapshot.get("terrainBodiesTransparency")) if isinstance(snapshot, dict) else None

            if rot_count is not None:
                rotated_counts[rot_count] += 1
            if bodies is not None:
                bodies_transparency[str(bodies)] += 1

            if fx_call is None or rot_count is None or rot_count <= 0:
                continue

            fx_render_calls_rotated += 1
            active[fx_call] = {
                "fx_call": fx_call,
                "tid": _get_int(obj, "tid"),
                "snapshot": snapshot if isinstance(snapshot, dict) else None,
                "entries": None,
                "batch_types": [],
                "draws_shadow": 0,
                "draws_color": 0,
                "rot_count": rot_count,
            }
            continue

        if event == "fx_queue_rotated_snapshot":
            fx_call = _get_int(obj, "fx_call")
            if fx_call is None or fx_call not in active:
                continue
            entries = obj.get("entries")
            if isinstance(entries, list):
                active[fx_call]["entries"] = entries
            continue

        if event == "grim_begin_batch":
            fx_call = _get_int(obj, "fx_call")
            if fx_call is None or fx_call not in active:
                continue
            batch_type = _get_str(obj, "batch_type")
            if isinstance(batch_type, str):
                active[fx_call]["batch_types"].append(batch_type)

                src = _get_int(obj, "state", "blend", "src")
                dst = _get_int(obj, "state", "blend", "dst")
                if src is not None and dst is not None:
                    key = f"{src}/{dst}"
                    if batch_type == "corpse_shadow":
                        blend_shadow[key] += 1
                    elif batch_type == "corpse_color":
                        blend_color[key] += 1
            continue

        if event == "grim_draw_quad":
            fx_call = _get_int(obj, "fx_call")
            if fx_call is None or fx_call not in active:
                continue
            batch_type = _get_str(obj, "batch_type")
            if batch_type not in ("corpse_shadow", "corpse_color"):
                continue

            draw_index = _get_int(obj, "draw_index")
            if draw_index is None or draw_index < 0:
                continue

            ctx = active[fx_call]
            entries = ctx.get("entries")
            if not isinstance(entries, list) or draw_index >= len(entries):
                continue
            entry = entries[draw_index]
            if not isinstance(entry, dict):
                continue

            snapshot = ctx.get("snapshot")
            terrain_scale = _as_float(snapshot.get("terrain_scale")) if isinstance(snapshot, dict) else None
            inv_scale = _as_float(snapshot.get("inv_scale")) if isinstance(snapshot, dict) else None
            if inv_scale is None and terrain_scale is not None and terrain_scale != 0.0:
                inv_scale = 1.0 / terrain_scale
            # World size is 1024; offset = 2*scale/1024.
            offset = (2.0 * terrain_scale / 1024.0) if terrain_scale is not None else None

            top_left_x = _as_float(entry.get("top_left_x"))
            top_left_y = _as_float(entry.get("top_left_y"))
            scale = _as_float(entry.get("scale"))
            rotation = _as_float(entry.get("rotation"))
            frame = _as_int(entry.get("corpse_frame"))

            color = entry.get("color")
            stored_a = _as_float(color.get("a")) if isinstance(color, dict) else None

            if batch_type == "corpse_shadow":
                exp_x = ((top_left_x - 0.5) * inv_scale - offset) if (top_left_x is not None and inv_scale is not None and offset is not None) else None
                exp_y = ((top_left_y - 0.5) * inv_scale - offset) if (top_left_y is not None and inv_scale is not None and offset is not None) else None
                exp_w = (scale * inv_scale * 1.064) if (scale is not None and inv_scale is not None) else None
                exp_h = exp_w
                exp_rot = (rotation - (math.pi * 0.5)) if rotation is not None else None
                exp_a = (stored_a * 0.5) if stored_a is not None else None
                ctx["draws_shadow"] += 1
            else:
                exp_x = (top_left_x * inv_scale - offset) if (top_left_x is not None and inv_scale is not None and offset is not None) else None
                exp_y = (top_left_y * inv_scale - offset) if (top_left_y is not None and inv_scale is not None and offset is not None) else None
                exp_w = (scale * inv_scale) if (scale is not None and inv_scale is not None) else None
                exp_h = exp_w
                exp_rot = (rotation - (math.pi * 0.5)) if rotation is not None else None
                exp_a = stored_a
                ctx["draws_color"] += 1

            obs_x = _get_float(obj, "xywh", "x")
            obs_y = _get_float(obj, "xywh", "y")
            obs_w = _get_float(obj, "xywh", "w")
            obs_h = _get_float(obj, "xywh", "h")
            obs_rot = _get_float(obj, "state", "rotation")
            obs_a = _get_float(obj, "state", "color", "a")
            obs_uv = _get(obj, "state", "uv")

            # Errors (only update when both values exist).
            x_err = _abs_err(obs_x, exp_x)
            y_err = _abs_err(obs_y, exp_y)
            w_err = _abs_err(obs_w, exp_w)
            h_err = _abs_err(obs_h, exp_h)
            r_err = _rot_err(obs_rot, exp_rot)
            a_err = _abs_err(obs_a, exp_a)

            if x_err is not None:
                err_xy.add(x_err)
            if y_err is not None:
                err_xy.add(y_err)
            if w_err is not None:
                err_wh.add(w_err)
            if h_err is not None:
                err_wh.add(h_err)
            if r_err is not None:
                err_rot.add(r_err)
            if a_err is not None:
                err_alpha.add(a_err)

            if isinstance(obs_uv, dict) and frame is not None:
                exp_uv = _expected_uv(frame)
                for k in ("u0", "v0", "u1", "v1"):
                    uv_err = _abs_err(_as_float(obs_uv.get(k)), exp_uv.get(k))
                    if uv_err is not None:
                        err_uv.add(uv_err)

            bad = False
            if x_err is not None and x_err > eps_xy:
                bad = True
            if y_err is not None and y_err > eps_xy:
                bad = True
            if w_err is not None and w_err > eps_xy:
                bad = True
            if h_err is not None and h_err > eps_xy:
                bad = True
            if r_err is not None and r_err > eps_rot:
                bad = True
            if a_err is not None and a_err > eps_alpha:
                bad = True
            if isinstance(obs_uv, dict) and frame is not None:
                exp_uv = _expected_uv(frame)
                for k in ("u0", "v0", "u1", "v1"):
                    uv_err = _abs_err(_as_float(obs_uv.get(k)), exp_uv.get(k))
                    if uv_err is not None and uv_err > eps_uv:
                        bad = True

            if bad and len(mismatches) < 20:
                mismatches.append(
                    {
                        "fx_call": fx_call,
                        "batch_type": batch_type,
                        "draw_index": draw_index,
                        "entry": {
                            "top_left_x": top_left_x,
                            "top_left_y": top_left_y,
                            "scale": scale,
                            "rotation": rotation,
                            "corpse_frame": frame,
                            "stored_alpha": stored_a,
                        },
                        "observed": {"x": obs_x, "y": obs_y, "w": obs_w, "h": obs_h, "rotation": obs_rot, "alpha": obs_a, "uv": obs_uv},
                        "expected": {"x": exp_x, "y": exp_y, "w": exp_w, "h": exp_h, "rotation": exp_rot, "alpha": exp_a, "uv": _expected_uv(frame) if frame is not None else None},
                        "errors": {
                            "xy": {"x": x_err, "y": y_err},
                            "wh": {"w": w_err, "h": h_err},
                            "rotation": r_err,
                            "alpha": a_err,
                        },
                    }
                )
            continue

        if event == "fx_queue_render_exit":
            fx_call = _get_int(obj, "fx_call")
            if fx_call is None or fx_call not in active:
                continue
            ctx = active.pop(fx_call)

            rot_count = _as_int(ctx.get("rot_count"))
            draws_shadow = _as_int(ctx.get("draws_shadow")) or 0
            draws_color = _as_int(ctx.get("draws_color")) or 0
            batch_types = ctx.get("batch_types")

            # Expect shadow batch first, then color batch (for any non-zero rotated queue).
            order_ok = False
            if isinstance(batch_types, list):
                filtered = [b for b in batch_types if b in ("corpse_shadow", "corpse_color")]
                order_ok = filtered[:2] == ["corpse_shadow", "corpse_color"]

            if order_ok:
                batch_order_ok += 1
            else:
                batch_order_bad += 1
                if len(mismatches) < 20:
                    mismatches.append(
                        {
                            "fx_call": fx_call,
                            "kind": "batch_order",
                            "batch_types": batch_types,
                            "rot_count": rot_count,
                            "draws_shadow": draws_shadow,
                            "draws_color": draws_color,
                        }
                    )

            if rot_count is not None:
                if draws_shadow != rot_count or draws_color != rot_count:
                    if len(mismatches) < 20:
                        mismatches.append(
                            {
                                "fx_call": fx_call,
                                "kind": "draw_count",
                                "rot_count": rot_count,
                                "draws_shadow": draws_shadow,
                                "draws_color": draws_color,
                            }
                        )
            continue

    summary: dict[str, Any] = {
        "events": {
            "fx_queue_render_calls": fx_render_calls,
            "fx_queue_render_calls_with_rotated": fx_render_calls_rotated,
        },
        "rotated_counts": {str(k): v for k, v in sorted(rotated_counts.items())},
        "terrainBodiesTransparency": dict(bodies_transparency),
        "validation": {
            "eps": {"xy": eps_xy, "rotation": eps_rot, "uv": eps_uv, "alpha": eps_alpha},
            "batch_order": {"ok": batch_order_ok, "bad": batch_order_bad},
            "blend": {
                "corpse_shadow": dict(blend_shadow),
                "corpse_color": dict(blend_color),
            },
            "errors": {
                "xy_abs": err_xy.as_dict(),
                "wh_abs": err_wh.as_dict(),
                "rotation_abs": err_rot.as_dict(),
                "alpha_abs": err_alpha.as_dict(),
                "uv_abs": err_uv.as_dict(),
            },
            "mismatches": mismatches,
        },
        "notes": {
            "corpse_shadow_blend": "Shadow pass uses src=ZERO, dst=INVSRCALPHA -> dst_rgb *= (1 - src_alpha).",
            "corpse_shadow_alpha": "Shadow pass uses entry alpha * 0.5 (entry alpha already adjusted by terrainBodiesTransparency or *0.8).",
            "corpse_rotation": "Both passes use rotation - (pi/2).",
            "corpse_shadow_geometry": "x,y=(top_left-0.5)*inv_scale - offset; size=scale*inv_scale*1.064.",
            "corpse_color_geometry": "x,y=top_left*inv_scale - offset; size=scale*inv_scale.",
            "offset": "offset = 2*terrain_scale/1024 = terrain_scale/512.",
        },
        "session": None,
        "script": "scripts/frida/fx_queue_render_trace.js",
        "source_log": str(log_path),
    }

    if session_init is not None:
        summary["session"] = {
            "ts": session_init.get("ts"),
            "process": session_init.get("process"),
            "exe": session_init.get("exe"),
            "grim": session_init.get("grim"),
            "config": session_init.get("config"),
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

