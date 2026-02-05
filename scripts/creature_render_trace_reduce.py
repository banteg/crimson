from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
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


def _get_float_list(obj: dict[str, Any], key: str) -> list[float] | None:
    value = obj.get(key)
    if not isinstance(value, list):
        return None
    out: list[float] = []
    for entry in value:
        f = _as_float(entry)
        if f is None:
            return None
        out.append(float(f))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Reduce creature_render_trace.jsonl into mismatch stats.")
    parser.add_argument("--log", required=True, help="Path to creature_render_trace.jsonl")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    log_path = Path(args.log)
    out_path = Path(args.out)

    events_total = 0
    events_draw = 0
    session: dict[str, Any] | None = None

    by_pass_id: Counter[int] = Counter()
    by_pass_name: Counter[str] = Counter()
    by_type: Counter[int] = Counter()

    hitbox_stats: dict[tuple[int, int], RunningStats] = defaultdict(RunningStats)  # (type_id, pass_id)

    frame_mismatches = 0
    alpha_mismatches = 0
    mismatch_examples: list[dict[str, Any]] = []

    # D3D floats are typically stable at ~1e-6, but keep a small epsilon because
    # some JSON logs may round.
    alpha_eps = 1e-4

    for obj in iter_jsonl(log_path):
        events_total += 1
        if obj.get("event") == "start" and session is None:
            session = obj
            continue
        if obj.get("event") != "creature_draw":
            continue

        events_draw += 1
        type_id = _get_int(obj, "type_id")
        pass_id = _get_int(obj, "pass_id")
        pass_name = obj.get("pass")
        if isinstance(type_id, int):
            by_type[type_id] += 1
        if isinstance(pass_id, int):
            by_pass_id[pass_id] += 1
        if isinstance(pass_name, str):
            by_pass_name[pass_name] += 1

        hitbox = _get_float(obj, "creature", "hitbox_size_f32")
        if type_id is not None and pass_id is not None and hitbox is not None:
            hitbox_stats[(type_id, pass_id)].add(hitbox)

        frame_obs = _get_int(obj, "atlas", "frame")
        frame_pred = _get_int(obj, "predicted", "frame")
        if frame_obs is not None and frame_pred is not None and frame_obs != frame_pred:
            frame_mismatches += 1
            if len(mismatch_examples) < 12:
                mismatch_examples.append(
                    {
                        "kind": "frame",
                        "seq": obj.get("seq"),
                        "type_id": type_id,
                        "pass_id": pass_id,
                        "frame_obs": frame_obs,
                        "frame_pred": frame_pred,
                        "hitbox": hitbox,
                    }
                )

        color = _get_float_list(obj, "color")
        alpha_obs = color[3] if color and len(color) >= 4 else None
        alpha_pred = _get_float(obj, "predicted", "alpha")
        if alpha_obs is not None and alpha_pred is not None and abs(alpha_obs - alpha_pred) > alpha_eps:
            alpha_mismatches += 1
            if len(mismatch_examples) < 12:
                mismatch_examples.append(
                    {
                        "kind": "alpha",
                        "seq": obj.get("seq"),
                        "type_id": type_id,
                        "pass_id": pass_id,
                        "alpha_obs": alpha_obs,
                        "alpha_pred": alpha_pred,
                        "hitbox": hitbox,
                    }
                )

    per_type: dict[str, Any] = {}
    for type_id, count in sorted(by_type.items()):
        per_type[str(type_id)] = {"events": count}

    per_pass: dict[str, Any] = {}
    for pass_id, count in sorted(by_pass_id.items()):
        per_pass[str(pass_id)] = {"events": count}

    per_type_pass: dict[str, Any] = {}
    for (type_id, pass_id), stats in sorted(hitbox_stats.items()):
        key = f"type_{type_id}_pass_{pass_id}"
        per_type_pass[key] = {"hitbox_size": stats.as_dict()}

    summary: dict[str, Any] = {
        "events_total": events_total,
        "events_creature_draw": events_draw,
        "session": None,
        "script": "scripts/frida/creature_render_trace.js",
        "source_log": session.get("logPath") if session else None,
        "counts": {
            "by_pass_id": {str(k): v for k, v in sorted(by_pass_id.items())},
            "by_pass": dict(by_pass_name),
            "by_type_id": {str(k): v for k, v in sorted(by_type.items())},
        },
        "mismatches": {
            "frame": {"count": frame_mismatches},
            "alpha": {"count": alpha_mismatches, "eps": alpha_eps},
            "examples": mismatch_examples,
        },
        "by_type_id": per_type,
        "by_pass_id": per_pass,
        "by_type_id_pass_id": per_type_pass,
        "notes": {
            "config_var_0x13": "GRIM_CFG_SRC_BLEND (D3DRS_SRCBLEND); creature_render_type uses 1=ZERO for shadow and 5=SRCALPHA for main.",
            "config_var_0x14": "GRIM_CFG_DEST_BLEND (D3DRS_DESTBLEND); creature_render_type sets 6=INVSRCALPHA for both passes.",
            "shadow_effect": "With src_blend=ZERO and dst_blend=INVSRCALPHA, pixels are darkened by dst *= (1 - src_alpha). Source RGB is ignored.",
        },
    }
    if session is not None:
        summary["session"] = {
            "exe_base": session.get("exe_base"),
            "grim_base": session.get("grim_base"),
            "logPath": session.get("logPath"),
            "config": session.get("config"),
            "ts": session.get("ts"),
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
