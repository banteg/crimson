from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

PREFERRED_SOURCES = ("stack_arg0", "stack_arg1", "eax", "edx", "ecx")


def iter_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
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
                rows.append(obj)
    return rows


def normalize_static(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.startswith(("0x", "0X")):
            return f"0x{int(text, 16):08x}"
        return f"0x{int(text, 16):08x}"
    except ValueError:
        return None


def vec2_from_entry(entry: dict[str, Any]) -> tuple[float, float] | None:
    vec2 = entry.get("vec2")
    if not isinstance(vec2, dict):
        return None
    x = vec2.get("x")
    y = vec2.get("y")
    if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
        return None
    return (float(x), float(y))


def vec2_len(value: tuple[float, float]) -> float:
    x, y = value
    return math.sqrt(x * x + y * y)


def pick_vec_pair(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    before_by_key: dict[tuple[str, str], tuple[float, float]] = {}
    after_by_key: dict[tuple[str, str], tuple[float, float]] = {}

    for row in before_rows:
        source = row.get("source")
        ptr = row.get("ptr")
        if not isinstance(source, str) or not isinstance(ptr, str):
            continue
        vec = vec2_from_entry(row)
        if vec is None:
            continue
        before_by_key[(source, ptr)] = vec

    for row in after_rows:
        source = row.get("source")
        ptr = row.get("ptr")
        if not isinstance(source, str) or not isinstance(ptr, str):
            continue
        vec = vec2_from_entry(row)
        if vec is None:
            continue
        after_by_key[(source, ptr)] = vec

    for source in PREFERRED_SOURCES:
        for key, before_vec in before_by_key.items():
            key_source, key_ptr = key
            if key_source != source:
                continue
            after_vec = after_by_key.get(key)
            if after_vec is None:
                continue
            return {
                "source": key_source,
                "ptr": key_ptr,
                "before": {"x": before_vec[0], "y": before_vec[1]},
                "after": {"x": after_vec[0], "y": after_vec[1]},
                "len_before": vec2_len(before_vec),
                "len_after": vec2_len(after_vec),
            }

    shared_keys = sorted(set(before_by_key.keys()) & set(after_by_key.keys()))
    if not shared_keys:
        return None

    key = shared_keys[0]
    before_vec = before_by_key[key]
    after_vec = after_by_key[key]
    return {
        "source": key[0],
        "ptr": key[1],
        "before": {"x": before_vec[0], "y": before_vec[1]},
        "after": {"x": after_vec[0], "y": after_vec[1]},
        "len_before": vec2_len(before_vec),
        "len_after": vec2_len(after_vec),
    }


def summarize(log_path: Path) -> dict[str, Any]:
    rows = iter_jsonl(log_path)
    start_event = next((row for row in rows if row.get("event") == "start"), None)
    calls = [row for row in rows if row.get("event") == "thunk_452f1d_call"]

    caller_counts: Counter[str] = Counter()
    callback_after_counts: Counter[str] = Counter()
    callback_transition_counts: Counter[str] = Counter()
    selected_pairs: list[dict[str, Any]] = []

    for call in calls:
        caller = call.get("caller")
        if isinstance(caller, dict):
            key = normalize_static(caller.get("static")) or str(caller.get("runtime") or "unknown")
            caller_counts[key] += 1

        before_target = call.get("callback_target_before")
        after_target = call.get("callback_target_after")
        before_static = normalize_static(before_target.get("static")) if isinstance(before_target, dict) else None
        after_static = normalize_static(after_target.get("static")) if isinstance(after_target, dict) else None
        if after_static is not None:
            callback_after_counts[after_static] += 1
        transition_key = f"{before_static or 'unknown'}->{after_static or 'unknown'}"
        callback_transition_counts[transition_key] += 1

        before_rows = call.get("pointer_candidates_before")
        after_rows = call.get("pointer_candidates_after")
        if not isinstance(before_rows, list) or not isinstance(after_rows, list):
            continue
        pair = pick_vec_pair(before_rows, after_rows)
        if pair is None:
            continue
        pair["seq"] = call.get("seq")
        pair["caller_static"] = normalize_static((call.get("caller") or {}).get("static"))
        selected_pairs.append(pair)

    lengths_before = [row["len_before"] for row in selected_pairs]
    lengths_after = [row["len_after"] for row in selected_pairs]
    unit_after_count = sum(1 for value in lengths_after if abs(value - 1.0) <= 1e-3)

    transition_rows: list[dict[str, Any]] = []
    for key, count in callback_transition_counts.most_common():
        before, _, after = key.partition("->")
        transition_rows.append({"from": before, "to": after, "count": count})

    summary = {
        "log_path": str(log_path),
        "thunk_static": normalize_static((start_event or {}).get("thunk_static")),
        "thunk_callback_ptr_static": normalize_static((start_event or {}).get("thunk_callback_ptr_static")),
        "call_count": len(calls),
        "callers": [{"caller_static": key, "count": count} for key, count in caller_counts.most_common()],
        "callback_target_after_counts": [
            {"target_static": key, "count": count}
            for key, count in callback_after_counts.most_common()
        ],
        "callback_transition_counts": transition_rows,
        "vector_length_observations": {
            "sample_count": len(selected_pairs),
            "unit_after_count": unit_after_count,
            "len_before_min": min(lengths_before) if lengths_before else None,
            "len_before_max": max(lengths_before) if lengths_before else None,
            "len_after_min": min(lengths_after) if lengths_after else None,
            "len_after_max": max(lengths_after) if lengths_after else None,
        },
        "selected_vector_samples": selected_pairs,
    }
    return summary


def build_name_map_candidates(summary: dict[str, Any]) -> list[dict[str, Any]]:
    call_count = int(summary.get("call_count") or 0)
    vectors = summary.get("vector_length_observations") or {}
    unit_after_count = int(vectors.get("unit_after_count") or 0)

    candidates: list[dict[str, Any]] = []
    if summary.get("thunk_static") == "0x00452f1d":
        candidates.append(
            {
                "program": "crimsonland.exe",
                "address": "0x00452f1d",
                "name": "vec2_normalize_dispatch_init",
                "signature": "float * vec2_normalize_dispatch_init(float *dst, float *src)",
                "comment": (
                    "capture-driven: lazy init calls renderer_select_backend(1) then jumps via DAT_00479658; "
                    f"calls={call_count}, unit_after={unit_after_count}"
                ),
            },
        )
        candidates.append(
            {
                "program": "crimsonland.exe",
                "address": "0x00452f2a",
                "name": "vec2_normalize_dispatch",
                "signature": "float * vec2_normalize_dispatch(float *dst, float *src)",
                "comment": "capture-driven: hot-path thunk that tail-jumps via DAT_00479658 after lazy init",
            },
        )

    after_counts = summary.get("callback_target_after_counts")
    if isinstance(after_counts, list) and after_counts:
        top = after_counts[0]
        if isinstance(top, dict) and top.get("target_static") == "0x00455587":
            candidates.append(
                {
                    "program": "crimsonland.exe",
                    "address": "0x00455587",
                    "name": "vec2_normalize_safe",
                    "signature": "float * vec2_normalize_safe(float *dst, float *src)",
                    "comment": (
                        "capture-driven: DAT_00479658 callback target after init; "
                        "normalizes src into dst and zeroes near-zero vectors"
                    ),
                },
            )

    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize thunk_452f1d runtime trace and emit name-map candidates.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("artifacts/frida/share/thunk_452f1d_trace.jsonl"),
        help="trace JSONL path",
    )
    parser.add_argument(
        "--out-summary",
        type=Path,
        default=Path("analysis/frida/thunk_452f1d_trace_summary.json"),
        help="summary JSON output path",
    )
    parser.add_argument(
        "--out-candidates",
        type=Path,
        default=Path("analysis/frida/thunk_452f1d_name_map_candidates.json"),
        help="name-map candidate JSON output path",
    )
    args = parser.parse_args()

    summary = summarize(args.log)
    candidates = build_name_map_candidates(summary)

    args.out_summary.parent.mkdir(parents=True, exist_ok=True)
    args.out_summary.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    args.out_candidates.parent.mkdir(parents=True, exist_ok=True)
    args.out_candidates.write_text(json.dumps(candidates, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print(f"wrote {args.out_summary}")
    print(f"wrote {args.out_candidates}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
