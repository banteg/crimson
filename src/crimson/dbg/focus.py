from __future__ import annotations

from pathlib import Path

from .channel_compare import compare_entity_samples, compare_rng_stream, compare_sim_state
from .channel_helpers import (
    ENTITY_SAMPLE_KINDS,
    entity_rows,
    entity_samples_channel,
    rng_stream_channel,
    sim_state_channel,
)
from .checkpoint_codec import channel_to_checkpoint
from .checkpoint_diff import DEFAULT_RNG_MARK_ORDER, checkpoint_deepdiff
from .policy import ParityPolicy
from .schema import TickRecord
from .trace import TraceReader


def _entity_uid_set(row: TickRecord | None, kind: str) -> set[int]:
    if row is None:
        return set()
    samples = entity_samples_channel(row)
    if samples is None:
        return set()
    out: set[int] = set()
    for item in entity_rows(samples, kind=kind):
        out.add(int(item.uid))
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

    checkpoint_diff = checkpoint_deepdiff(
        expected_checkpoint,
        candidate_checkpoint,
        include_hash_fields=bool(policy.include_hash_fields),
        include_rng_fields=bool(policy.include_rng_fields),
        ignore_field_prefixes=policy.ignore_field_prefixes,
        elapsed_baseline=None,
        max_diffs=int(policy.max_field_diffs),
        float_abs_tol=float(policy.float_abs_tol),
        float_ulp_tol=int(policy.float_ulp_tol),
    )

    expected_rng = {str(key): int(value) for key, value in expected_checkpoint.rng_marks.items()}
    candidate_rng = {str(key): int(value) for key, value in candidate_checkpoint.rng_marks.items()}
    mismatching_rng = [key for key in sorted(set(expected_rng) | set(candidate_rng)) if expected_rng.get(key) != candidate_rng.get(key)]
    first_rng_mark = None
    if mismatching_rng:
        first_rng_mark = next((mark for mark in DEFAULT_RNG_MARK_ORDER if mark in mismatching_rng), mismatching_rng[0])

    rng_ok, rng_stream_detail = compare_rng_stream(
        rng_stream_channel(expected_row),
        rng_stream_channel(candidate_row),
    )
    rng_stream = dict(rng_stream_detail or {})
    rng_stream["ok"] = bool(rng_ok)

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
    entity_samples_ok, entity_samples_detail = compare_entity_samples(
        entity_samples_channel(expected_row),
        entity_samples_channel(candidate_row),
    )
    sim_state_ok, sim_state_detail = compare_sim_state(
        sim_state_channel(expected_row),
        sim_state_channel(candidate_row),
    )

    diverged = bool(
        checkpoint_diff is not None
        or mismatching_rng
        or not bool(rng_stream.get("ok"))
        or entity_diverged
        or not entity_samples_ok
        or not sim_state_ok,
    )

    return {
        "tick_index": int(tick),
        "policy": str(policy.name),
        "diverged": diverged,
        "checkpoint_diff_count": (0 if checkpoint_diff is None else int(checkpoint_diff.diff_count)),
        "checkpoint_diff": (
            None
            if checkpoint_diff is None
            else {
                "payload": checkpoint_diff.payload,
                "pretty": checkpoint_diff.pretty,
            }
        ),
        "rng_marks": {
            "first_mismatch_mark": first_rng_mark,
            "mismatching_marks": mismatching_rng,
            "expected": expected_rng,
            "candidate": candidate_rng,
        },
        "rng_stream": rng_stream,
        "entity_presence": entity_presence,
        "entity_samples": {
            "ok": bool(entity_samples_ok),
            "detail": entity_samples_detail,
        },
        "sim_state": {
            "ok": bool(sim_state_ok),
            "detail": sim_state_detail,
        },
    }
