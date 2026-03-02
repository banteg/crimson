from __future__ import annotations

import ast
import re
from pathlib import Path

import msgspec

from .channel_helpers import ENTITY_SAMPLE_KINDS, as_object_dict, as_object_list
from .schema import TickRecord
from .trace import TraceReader

_QUERY_RE = re.compile(r"^\s*(ticks|entities)\s+where\s+(.+?)\s*$")
_COND_RE = re.compile(r"^\s*(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s*$")


class _Operand(msgspec.Struct, frozen=True):
    kind: str
    value: object


class _Predicate(msgspec.Struct, frozen=True):
    left: _Operand
    op: str
    right: _Operand


def _parse_literal(token: str) -> object:
    raw = token.strip()
    lower = raw.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower == "none" or lower == "null":
        return None
    try:
        return ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return raw


def _parse_operand(token: str) -> _Operand:
    raw = token.strip()
    if raw.startswith("prev(") and raw.endswith(")"):
        path = raw[5:-1].strip()
        if not path:
            raise ValueError("empty prev(...) field path")
        return _Operand(kind="prev_field", value=path)
    parsed = _parse_literal(raw)
    if parsed != raw:
        return _Operand(kind="literal", value=parsed)
    return _Operand(kind="field", value=raw)


def _parse_expression(expression: str) -> tuple[str, _Predicate]:
    scope_match = _QUERY_RE.match(expression)
    if scope_match is None:
        raise ValueError("expression must start with 'ticks where ...' or 'entities where ...'")
    scope = scope_match.group(1)
    condition = scope_match.group(2)
    cond_match = _COND_RE.match(condition)
    if cond_match is None:
        raise ValueError("expression condition must use one of: == != >= <= > <")
    left = _parse_operand(cond_match.group(1))
    op = cond_match.group(2)
    right = _parse_operand(cond_match.group(3))
    return scope, _Predicate(left=left, op=op, right=right)


def _resolve_path(root: dict[str, object], path: str) -> object:
    current: object = root
    for part in path.split("."):
        mapped = as_object_dict(current)
        if mapped is None:
            return None
        current = mapped.get(part)
    return current


def _to_float(value: object) -> float | None:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _eval_operand(
    operand: _Operand,
    *,
    current: dict[str, object],
    previous: dict[str, object] | None,
) -> object:
    if operand.kind == "literal":
        return operand.value
    if operand.kind == "field":
        return _resolve_path(current, str(operand.value))
    if operand.kind == "prev_field":
        if previous is None:
            return None
        return _resolve_path(previous, str(operand.value))
    raise ValueError(f"unsupported operand kind: {operand.kind}")


def _compare_values(left: object, op: str, right: object) -> bool:
    left_num = _to_float(left)
    right_num = _to_float(right)
    if left_num is not None and right_num is not None:
        if op == "==":
            return left_num == right_num
        if op == "!=":
            return left_num != right_num
        if op == ">=":
            return left_num >= right_num
        if op == "<=":
            return left_num <= right_num
        if op == ">":
            return left_num > right_num
        if op == "<":
            return left_num < right_num
        raise ValueError(f"unsupported comparison operator: {op}")

    if op == "==":
        return left == right
    if op == "!=":
        return left != right

    left_text = str(left)
    right_text = str(right)
    if op == ">=":
        return left_text >= right_text
    if op == "<=":
        return left_text <= right_text
    if op == ">":
        return left_text > right_text
    if op == "<":
        return left_text < right_text
    raise ValueError(f"unsupported comparison operator: {op}")


def _entity_rows(row: TickRecord) -> list[dict[str, object]]:
    entity_samples = as_object_dict(row.channels.get("entity_samples"))
    if entity_samples is None:
        return []
    out: list[dict[str, object]] = []
    for kind in ENTITY_SAMPLE_KINDS:
        rows = as_object_list(entity_samples.get(kind))
        for item in rows:
            mapped = as_object_dict(item)
            if mapped is None:
                continue
            payload = dict(mapped)
            if "pool_kind" not in payload:
                payload["pool_kind"] = kind
            out.append(payload)
    return out


def _event_type_counts(row: TickRecord) -> dict[str, int]:
    checkpoint = as_object_dict(row.channels.get("checkpoint"))
    if checkpoint is not None:
        events = as_object_dict(checkpoint.get("events"))
        if events is not None:
            return {
                "hit_count": int(events.get("hit_count", 0)) if isinstance(events.get("hit_count"), (int, float)) else 0,
                "pickup_count": int(events.get("pickup_count", 0))
                if isinstance(events.get("pickup_count"), (int, float))
                else 0,
                "sfx_count": int(events.get("sfx_count", 0)) if isinstance(events.get("sfx_count"), (int, float)) else 0,
            }
    return {}


def tick_summary_from_row(row: TickRecord) -> dict[str, object]:
    checkpoint = as_object_dict(row.channels.get("checkpoint")) or {}
    rng_marks = as_object_dict(row.channels.get("rng_marks")) or {}
    entity_samples = as_object_dict(row.channels.get("entity_samples")) or {}

    entity_counts: dict[str, int] = {}
    for kind in ENTITY_SAMPLE_KINDS:
        entity_counts[kind] = len(as_object_list(entity_samples.get(kind)))

    event_counts = _event_type_counts(row)
    event_count_total = sum(event_counts.values())
    event_types_sorted = sorted(event_counts.items(), key=lambda item: (-item[1], item[0]))
    top_event_types = [f"{name}:{count}" for name, count in event_types_sorted[:8]]

    return {
        "tick_index": row.tick_index,
        "elapsed_ms": row.elapsed_ms,
        "dt_ms_i32": row.dt_ms_i32,
        "mode_id": row.mode_id,
        "phase_markers": list(row.phase_markers),
        "checkpoint": checkpoint,
        "rng_marks": rng_marks,
        "entity_counts": entity_counts,
        "event_count_total": event_count_total,
        "top_event_types": top_event_types,
    }


def summarize_tick(*, trace_path: Path, tick_index: int) -> dict[str, object]:
    with TraceReader(Path(trace_path)) as trace:
        row = trace.tick(tick_index)
        if row is None:
            raise ValueError(f"tick {tick_index} not found")
        return tick_summary_from_row(row)


def parse_tick_range(value: str | None) -> tuple[int | None, int | None]:
    if value is None:
        return None, None
    raw = value.strip()
    if not raw:
        return None, None
    if ".." not in raw:
        tick = int(raw)
        return tick, tick

    left_raw, right_raw = raw.split("..", maxsplit=1)
    left = int(left_raw) if left_raw.strip() else None
    right = int(right_raw) if right_raw.strip() else None
    if left is not None and right is not None and left > right:
        raise ValueError(f"invalid tick range {value!r}: start > end")
    return left, right


def entity_history(
    *,
    trace_path: Path,
    entity_uid: int,
    tick_start: int | None = None,
    tick_end: int | None = None,
) -> dict[str, object]:
    snapshots: list[dict[str, object]] = []
    with TraceReader(Path(trace_path)) as trace:
        for row in trace.iter_ticks(tick_start=tick_start, tick_end=tick_end):
            for entity in _entity_rows(row):
                uid_value = entity.get("uid")
                if not isinstance(uid_value, int):
                    continue
                if uid_value != entity_uid:
                    continue
                snapshot = dict(entity)
                snapshot["tick_index"] = row.tick_index
                snapshots.append(snapshot)

    if not snapshots:
        raise ValueError(f"entity uid {entity_uid} not found in requested range")

    first = snapshots[0]
    spawn_tick = snapshots[0].get("tick_index")
    despawn_tick = snapshots[-1].get("tick_index")
    if not isinstance(spawn_tick, int) or not isinstance(despawn_tick, int):
        raise TypeError("entity snapshot missing integer tick_index")
    return {
        "entity_uid": entity_uid,
        "pool_kind": str(first.get("pool_kind", "unknown")),
        "spawn_tick": spawn_tick,
        "despawn_tick": despawn_tick,
        "samples": snapshots,
    }


def query_trace(
    *,
    trace_path: Path,
    expression: str,
    limit: int = 256,
) -> dict[str, object]:
    scope, predicate = _parse_expression(expression)
    limit_value = max(1, limit)

    rows: list[dict[str, object]] = []
    matched_count = 0
    with TraceReader(Path(trace_path)) as trace:
        if scope == "ticks":
            prev_context: dict[str, object] | None = None
            for row in trace.iter_ticks():
                context = tick_summary_from_row(row)
                left = _eval_operand(predicate.left, current=context, previous=prev_context)
                right = _eval_operand(predicate.right, current=context, previous=prev_context)
                if _compare_values(left, predicate.op, right):
                    matched_count += 1
                    if len(rows) < limit_value:
                        rows.append(context)
                prev_context = context
        else:
            for row in trace.iter_ticks():
                tick_index = row.tick_index
                for entity in _entity_rows(row):
                    context = {"tick_index": tick_index, **entity}
                    left = _eval_operand(predicate.left, current=context, previous=None)
                    right = _eval_operand(predicate.right, current=context, previous=None)
                    if _compare_values(left, predicate.op, right):
                        matched_count += 1
                        if len(rows) < limit_value:
                            rows.append(context)

    return {
        "scope": scope,
        "expression": expression,
        "limit": limit_value,
        "match_count": matched_count,
        "truncated": bool(matched_count > len(rows)),
        "rows": rows,
    }
