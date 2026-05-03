from __future__ import annotations

import json
from collections.abc import Sequence

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .payloads import BuiltinObject, to_builtin_object
from .strict_compare import strict_mismatch_payload


class ReplayDiffFailure(msgspec.Struct, frozen=True):
    kind: str
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None = None


class ReplayDiffResult(msgspec.Struct, frozen=True):
    ok: bool
    checked_count: int
    first_rng_only_tick: int | None = None
    failure: ReplayDiffFailure | None = None
    skipped_elapsed_mismatch_count: int = 0


class CheckpointDeepDiff(msgspec.Struct, frozen=True):
    payload: BuiltinObject
    pretty: str
    diff_count: int


def _checkpoint_to_obj(
    checkpoint: ReplayCheckpoint,
    *,
    include_rng_fields: bool,
) -> BuiltinObject:
    obj = to_builtin_object(checkpoint, field="checkpoint")
    if not include_rng_fields:
        for key in ("rng_state",):
            obj.pop(key, None)
    return obj


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    *,
    include_rng_fields: bool = True,
) -> CheckpointDeepDiff | None:
    expected_obj = _checkpoint_to_obj(expected, include_rng_fields=bool(include_rng_fields))
    actual_obj = _checkpoint_to_obj(actual, include_rng_fields=bool(include_rng_fields))
    mismatches, diff_count, _pretty = strict_mismatch_payload(expected_obj, actual_obj)
    if int(diff_count) <= 0:
        return None

    payload = to_builtin_object({"mismatches": mismatches}, field="checkpoint_diff.payload")
    return CheckpointDeepDiff(
        payload=payload,
        pretty=json.dumps(payload, sort_keys=True, indent=2, default=repr),
        diff_count=int(diff_count),
    )


def compare_checkpoints(
    expected: Sequence[ReplayCheckpoint],
    actual: Sequence[ReplayCheckpoint],
    *,
    skip_elapsed_mismatch: bool = False,
) -> ReplayDiffResult:
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    first_rng_only_tick: int | None = None
    checked_count = 0
    skipped_elapsed_mismatch_count = 0

    for exp in expected:
        checked_count += 1
        tick = int(exp.tick_index)
        act = (actual_by_tick[tick] if tick in actual_by_tick else None)
        if act is None:
            return ReplayDiffResult(
                ok=False,
                checked_count=checked_count,
                first_rng_only_tick=first_rng_only_tick,
                failure=ReplayDiffFailure(
                    kind="missing_checkpoint",
                    tick_index=tick,
                    expected=exp,
                    actual=None,
                ),
                skipped_elapsed_mismatch_count=skipped_elapsed_mismatch_count,
            )

        if exp == act:
            continue

        if bool(skip_elapsed_mismatch) and int(exp.elapsed_ms) != int(act.elapsed_ms):
            skipped_elapsed_mismatch_count += 1
            continue

        exp_no_rng = _checkpoint_to_obj(exp, include_rng_fields=False)
        act_no_rng = _checkpoint_to_obj(act, include_rng_fields=False)
        if exp_no_rng == act_no_rng:
            if first_rng_only_tick is None:
                first_rng_only_tick = tick
            continue

        return ReplayDiffResult(
            ok=False,
            checked_count=checked_count,
            first_rng_only_tick=first_rng_only_tick,
                failure=ReplayDiffFailure(
                    kind="state_mismatch",
                    tick_index=tick,
                    expected=exp,
                    actual=act,
                ),
                skipped_elapsed_mismatch_count=skipped_elapsed_mismatch_count,
            )

    return ReplayDiffResult(
        ok=True,
        checked_count=checked_count,
        first_rng_only_tick=first_rng_only_tick,
        failure=None,
        skipped_elapsed_mismatch_count=skipped_elapsed_mismatch_count,
    )
