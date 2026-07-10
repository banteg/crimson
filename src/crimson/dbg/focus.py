from __future__ import annotations

from pathlib import Path

from .channel_compare import (
    compare_entity_samples,
    compare_replay_step,
    compare_rng_stream,
    compare_sim_state,
    compare_timing_samples,
)
from .channel_helpers import (
    ENTITY_SAMPLE_KINDS,
    checkpoint_channel_required,
    entity_rows,
    entity_samples_channel_required,
    rng_stream_channel_required,
    sim_state_channel_required,
    timing_samples_channel_required,
)
from .checkpoint_diff import checkpoint_deepdiff
from .diff import validate_comparison_identity
from .payloads import BuiltinObject, to_builtin_object
from .schema import TickRecord
from .trace import TraceReader


def _entity_uid_set(row: TickRecord, kind: str) -> set[int]:
    samples = entity_samples_channel_required(row)
    out: set[int] = set()
    for item in entity_rows(samples, kind=kind):
        out.add(int(item.uid))
    return out


def focus_tick(
    *,
    golden_trace: Path,
    candidate_trace: Path,
    tick_index: int,
) -> BuiltinObject:
    tick = int(tick_index)
    with TraceReader(Path(golden_trace)) as expected, TraceReader(Path(candidate_trace)) as candidate:
        validate_comparison_identity(expected, candidate)
        expected_row = expected.tick(tick)
        candidate_row = candidate.tick(tick)

    if expected_row is None or candidate_row is None:
        raise ValueError(f"tick {tick} missing in one of the traces")

    expected_checkpoint = checkpoint_channel_required(expected_row)
    candidate_checkpoint = checkpoint_channel_required(candidate_row)

    checkpoint_diff = checkpoint_deepdiff(expected_checkpoint, candidate_checkpoint)

    replay_step_ok, replay_step_detail = compare_replay_step(
        expected_row.channels.replay_step,
        candidate_row.channels.replay_step,
    )

    rng_ok, rng_stream_detail = compare_rng_stream(
        rng_stream_channel_required(expected_row),
        rng_stream_channel_required(candidate_row),
    )
    rng_stream = dict(rng_stream_detail or {})
    rng_stream["ok"] = bool(rng_ok)

    entity_presence: BuiltinObject = {}
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
            "expected_count": len(expected_uids),
            "candidate_count": len(candidate_uids),
            "missing_uids": missing,
            "extra_uids": extra,
        }
    entity_samples_ok, entity_samples_detail = compare_entity_samples(
        entity_samples_channel_required(expected_row),
        entity_samples_channel_required(candidate_row),
    )
    sim_state_ok, sim_state_detail = compare_sim_state(
        sim_state_channel_required(expected_row),
        sim_state_channel_required(candidate_row),
    )
    expected_timing_samples = timing_samples_channel_required(expected_row)
    candidate_timing_samples = timing_samples_channel_required(candidate_row)
    timing_samples_ok, timing_samples_detail = compare_timing_samples(
        expected_timing_samples,
        candidate_timing_samples,
    )

    diverged = bool(
        checkpoint_diff is not None
        or not replay_step_ok
        or not bool(rng_stream.get("ok"))
        or entity_diverged
        or not entity_samples_ok
        or not sim_state_ok
        or not timing_samples_ok,
    )

    return to_builtin_object(
        {
            "tick_index": int(tick),
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
            "replay_step": {
                "ok": bool(replay_step_ok),
                "detail": replay_step_detail,
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
            "timing_samples": {
                "ok": bool(timing_samples_ok),
                "expected_count": len(expected_timing_samples),
                "candidate_count": len(candidate_timing_samples),
                "detail": timing_samples_detail,
            },
        },
        field="focus_tick",
    )
