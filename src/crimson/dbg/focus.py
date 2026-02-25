from __future__ import annotations

from pathlib import Path

from ..original.diff import DEFAULT_RNG_MARK_ORDER, checkpoint_field_diffs
from .channel_helpers import ENTITY_SAMPLE_KINDS, as_object_dict, as_object_list, rng_row_key
from .checkpoint_codec import channel_to_checkpoint
from .policy import ParityPolicy
from .schema import TickRecord
from .trace import TraceReader


def _rng_stream_alignment(expected_rows: list[object], candidate_rows: list[object]) -> dict[str, object]:
    exp_keys = [rng_row_key(row) for row in expected_rows]
    cand_keys = [rng_row_key(row) for row in candidate_rows]
    max_prefix = min(len(exp_keys), len(cand_keys))
    prefix = 0
    while prefix < max_prefix and exp_keys[prefix] == cand_keys[prefix]:
        prefix += 1
    detail: dict[str, object] = {
        "prefix_match_len": int(prefix),
        "expected_calls": int(len(exp_keys)),
        "candidate_calls": int(len(cand_keys)),
        "missing_tail": int(max(0, len(exp_keys) - len(cand_keys))),
        "extra_tail": int(max(0, len(cand_keys) - len(exp_keys))),
    }
    if prefix < len(expected_rows):
        detail["expected_first_mismatch"] = expected_rows[prefix]
    if prefix < len(candidate_rows):
        detail["candidate_first_mismatch"] = candidate_rows[prefix]
    detail["ok"] = bool(prefix == len(exp_keys) == len(cand_keys))
    return detail


def _entity_uid_set(row: TickRecord | None, kind: str) -> set[int]:
    if row is None:
        return set()
    entity_samples = as_object_dict(row.channels.get("entity_samples"))
    if entity_samples is None:
        return set()
    rows = as_object_list(entity_samples.get(kind))
    out: set[int] = set()
    for item in rows:
        mapped = as_object_dict(item)
        if mapped is None:
            continue
        uid_value = mapped.get("uid")
        if isinstance(uid_value, int):
            out.add(int(uid_value))
    return out


def _event_type_counts(row: TickRecord | None) -> dict[str, int]:
    if row is None:
        return {}
    out: dict[str, int] = {}
    for item in as_object_list(row.channels.get("event_heads")):
        mapped = as_object_dict(item)
        if mapped is None:
            key = str(type(item).__name__)
        else:
            type_obj = mapped.get("type")
            key = str(type_obj) if type_obj is not None else str(type(item).__name__)
        out[key] = int(out.get(key, 0)) + 1
    return out


def focus_tick(
    *,
    golden_trace: Path,
    candidate_trace: Path,
    tick_index: int,
    policy: ParityPolicy,
) -> dict[str, object]:
    tick = int(tick_index)
    with TraceReader(Path(golden_trace)) as expected, TraceReader(Path(candidate_trace)) as candidate:
        expected_row = expected.tick(tick)
        candidate_row = candidate.tick(tick)

    if expected_row is None or candidate_row is None:
        raise ValueError(f"tick {tick} missing in one of the traces")

    expected_checkpoint = channel_to_checkpoint(expected_row.channels.get("checkpoint"))
    candidate_checkpoint = channel_to_checkpoint(candidate_row.channels.get("checkpoint"))

    checkpoint_diffs = checkpoint_field_diffs(
        expected_checkpoint,
        candidate_checkpoint,
        include_hash_fields=bool(policy.include_hash_fields),
        include_rng_fields=bool(policy.include_rng_fields),
        normalize_unknown=bool(policy.normalize_unknown),
        unknown_events_wildcard=bool(policy.unknown_events_wildcard),
        elapsed_baseline=None,
        max_diffs=int(policy.max_field_diffs),
        float_abs_tol=float(policy.float_abs_tol),
    )
    checkpoint_fields = [
        {"field": str(item.field), "expected": item.expected, "candidate": item.actual}
        for item in checkpoint_diffs
    ]

    expected_rng = {str(key): int(value) for key, value in expected_checkpoint.rng_marks.items()}
    candidate_rng = {str(key): int(value) for key, value in candidate_checkpoint.rng_marks.items()}
    mismatching_rng = [key for key in sorted(set(expected_rng) | set(candidate_rng)) if expected_rng.get(key) != candidate_rng.get(key)]
    first_rng_mark = None
    if mismatching_rng:
        first_rng_mark = next((mark for mark in DEFAULT_RNG_MARK_ORDER if mark in mismatching_rng), mismatching_rng[0])

    rng_stream = _rng_stream_alignment(
        as_object_list(expected_row.channels.get("rng_stream_head")),
        as_object_list(candidate_row.channels.get("rng_stream_head")),
    )

    entity_presence: dict[str, object] = {}
    entity_diverged = False
    for kind in ENTITY_SAMPLE_KINDS:
        expected_uids = _entity_uid_set(expected_row, kind)
        candidate_uids = _entity_uid_set(candidate_row, kind)
        missing = sorted(expected_uids - candidate_uids)
        extra = sorted(candidate_uids - expected_uids)
        diverged = bool(missing or extra or len(expected_uids) != len(candidate_uids))
        if diverged:
            entity_diverged = True
        entity_presence[kind] = {
            "expected_count": int(len(expected_uids)),
            "candidate_count": int(len(candidate_uids)),
            "missing_uids": missing[:32],
            "extra_uids": extra[:32],
        }

    expected_event_types = _event_type_counts(expected_row)
    candidate_event_types = _event_type_counts(candidate_row)
    expected_micro_count = len(as_object_list(expected_row.channels.get("micro_traces")))
    candidate_micro_count = len(as_object_list(candidate_row.channels.get("micro_traces")))

    diverged = bool(
        checkpoint_fields
        or mismatching_rng
        or not bool(rng_stream.get("ok"))
        or entity_diverged
        or expected_event_types != candidate_event_types
        or expected_micro_count != candidate_micro_count,
    )

    return {
        "tick_index": int(tick),
        "policy": str(policy.name),
        "diverged": diverged,
        "checkpoint_field_count": int(len(checkpoint_fields)),
        "checkpoint_fields": checkpoint_fields,
        "rng_marks": {
            "first_mismatch_mark": first_rng_mark,
            "mismatching_marks": mismatching_rng,
            "expected": expected_rng,
            "candidate": candidate_rng,
        },
        "rng_stream": rng_stream,
        "entity_presence": entity_presence,
        "event_heads": {
            "expected_count": int(sum(expected_event_types.values())),
            "candidate_count": int(sum(candidate_event_types.values())),
            "expected_types": expected_event_types,
            "candidate_types": candidate_event_types,
        },
        "micro_traces": {
            "expected_count": int(expected_micro_count),
            "candidate_count": int(candidate_micro_count),
        },
    }
