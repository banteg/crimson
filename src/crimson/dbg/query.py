from __future__ import annotations

import ast
import re
from pathlib import Path

import msgspec

from .channel_helpers import (
    ENTITY_SAMPLE_KINDS,
    checkpoint_channel,
    entity_rows,
    entity_samples_channel,
)
from .payloads import BuiltinObject, BuiltinValue, coerce_builtin_value, to_builtin_object
from .schema import TickRecord
from .trace import TraceReader

_QUERY_RE = re.compile(r"^\s*(ticks|entities)\s+where\s+(.+?)\s*$")
_COND_RE = re.compile(r"^\s*(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s*$")


class _Operand(msgspec.Struct, frozen=True):
    kind: str
    value: BuiltinValue


class _Predicate(msgspec.Struct, frozen=True):
    left: _Operand
    op: str
    right: _Operand


def _parse_literal(token: str) -> BuiltinValue:
    raw = token.strip()
    lower = raw.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower == "none" or lower == "null":
        return None
    try:
        parsed = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return raw
    try:
        return coerce_builtin_value(parsed, field="query literal")
    except TypeError:
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


def _resolve_path(root: BuiltinObject, path: str) -> BuiltinValue | None:
    current: BuiltinValue = root
    for part in path.split("."):
        match current:
            case dict() as mapped:
                current = mapped.get(part)
            case _:
                return None
    return current


def _to_float(value: object) -> float | None:
    match value:
        case bool() as v:
            return float(int(v))
        case int() as v:
            return float(v)
        case float() as v:
            return v
        case str() as v:
            try:
                return float(v)
            except ValueError:
                return None
        case _:
            return None


def _eval_operand(
    operand: _Operand,
    *,
    current: BuiltinObject,
    previous: BuiltinObject | None,
) -> BuiltinValue | None:
    if operand.kind == "literal":
        return operand.value
    if operand.kind == "field":
        return _resolve_path(current, str(operand.value))
    if operand.kind == "prev_field":
        if previous is None:
            return None
        return _resolve_path(previous, str(operand.value))
    raise ValueError(f"unsupported operand kind: {operand.kind}")


def _compare_values(left: BuiltinValue | None, op: str, right: BuiltinValue | None) -> bool:
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


def _entity_rows(row: TickRecord) -> list[BuiltinObject]:
    samples = entity_samples_channel(row)
    if samples is None:
        return []
    out: list[BuiltinObject] = []
    for kind in ENTITY_SAMPLE_KINDS:
        for item in entity_rows(samples, kind=kind):
            out.append(to_builtin_object(item, field=f"entity_samples.{kind}"))
    return out


def _event_type_counts(row: TickRecord) -> dict[str, int]:
    checkpoint = checkpoint_channel(row)
    if checkpoint is None:
        return {}
    return {
        "hit_count": int(checkpoint.events.hit_count),
        "pickup_count": int(checkpoint.events.pickup_count),
        "sfx_count": int(checkpoint.events.sfx_count),
    }


def tick_summary_from_row(row: TickRecord) -> BuiltinObject:
    checkpoint_obj = checkpoint_channel(row)
    checkpoint = to_builtin_object(checkpoint_obj, field="checkpoint") if checkpoint_obj is not None else {}
    samples = entity_samples_channel(row)
    if samples is None:
        entity_counts = {kind: 0 for kind in ENTITY_SAMPLE_KINDS}
    else:
        entity_counts = {
            "creatures": len(samples.creatures),
            "projectiles": len(samples.projectiles),
            "secondary_projectiles": len(samples.secondary_projectiles),
            "bonuses": len(samples.bonuses),
        }

    event_counts = _event_type_counts(row)
    event_count_total = sum(event_counts.values())
    event_types_sorted = sorted(event_counts.items(), key=lambda item: (-item[1], item[0]))
    top_event_types = [f"{name}:{count}" for name, count in event_types_sorted[:8]]
    rng_stream_count = len(row.channels.rng_stream)
    timing_samples_count = len(row.channels.timing_samples)

    return to_builtin_object(
        {
            "tick_index": row.tick_index,
            "elapsed_ms": row.elapsed_ms,
            "dt_ms_i32": row.dt_ms_i32,
            "mode_id": row.mode_id,
            "checkpoint": checkpoint,
            "entity_counts": entity_counts,
            "rng_stream_count": rng_stream_count,
            "timing_samples_count": timing_samples_count,
            "event_count_total": event_count_total,
            "top_event_types": top_event_types,
        },
        field="tick_summary",
    )


def summarize_tick(*, trace_path: Path, tick_index: int) -> BuiltinObject:
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
) -> BuiltinObject:
    snapshots: list[BuiltinObject] = []
    spawn_tick: int | None = None
    despawn_tick: int | None = None
    with TraceReader(Path(trace_path)) as trace:
        for row in trace.iter_ticks(tick_start=tick_start, tick_end=tick_end):
            tick_value = int(row.tick_index)
            for entity in _entity_rows(row):
                uid_obj = entity.get("uid")
                if not isinstance(uid_obj, int):
                    continue
                if int(uid_obj) != int(entity_uid):
                    continue
                snapshot = dict(entity)
                snapshot["tick_index"] = tick_value
                snapshots.append(snapshot)
                if spawn_tick is None:
                    spawn_tick = tick_value
                despawn_tick = tick_value

    if not snapshots:
        raise ValueError(f"entity uid {entity_uid} not found in requested range")
    assert spawn_tick is not None
    assert despawn_tick is not None

    first = snapshots[0]
    return to_builtin_object(
        {
            "entity_uid": entity_uid,
            "pool_kind": str(first.get("pool_kind", "unknown")),
            "spawn_tick": int(spawn_tick),
            "despawn_tick": int(despawn_tick),
            "samples": snapshots,
        },
        field="entity_history",
    )


def query_trace(
    *,
    trace_path: Path,
    expression: str,
    limit: int = 256,
) -> BuiltinObject:
    scope, predicate = _parse_expression(expression)
    limit_value = max(1, limit)

    rows: list[BuiltinObject] = []
    matched_count = 0
    with TraceReader(Path(trace_path)) as trace:
        if scope == "ticks":
            prev_context: BuiltinObject | None = None
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

    return to_builtin_object(
        {
            "scope": scope,
            "expression": expression,
            "limit": limit_value,
            "match_count": matched_count,
            "truncated": bool(matched_count > len(rows)),
            "rows": rows,
        },
        field="query_trace",
    )
