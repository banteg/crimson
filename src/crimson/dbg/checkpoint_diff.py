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
    expected: ReplayCheckpoint | None = None
    actual: ReplayCheckpoint | None = None


class ReplayDiffResult(msgspec.Struct, frozen=True):
    ok: bool
    checked_count: int
    failure: ReplayDiffFailure | None = None


class CheckpointDeepDiff(msgspec.Struct, frozen=True):
    payload: BuiltinObject
    pretty: str
    diff_count: int


def _checkpoint_to_obj(checkpoint: ReplayCheckpoint) -> BuiltinObject:
    return to_builtin_object(checkpoint, field="checkpoint")


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
) -> CheckpointDeepDiff | None:
    expected_obj = _checkpoint_to_obj(expected)
    actual_obj = _checkpoint_to_obj(actual)
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
) -> ReplayDiffResult:
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    if len(expected_by_tick) != len(expected):
        raise ValueError("expected checkpoints contain duplicate tick indices")
    if len(actual_by_tick) != len(actual):
        raise ValueError("actual checkpoints contain duplicate tick indices")
    checked_count = 0

    for tick in sorted(set(expected_by_tick) | set(actual_by_tick)):
        checked_count += 1
        exp = expected_by_tick.get(tick)
        act = actual_by_tick.get(tick)
        if exp is None:
            return ReplayDiffResult(
                ok=False,
                checked_count=checked_count,
                failure=ReplayDiffFailure(
                    kind="extra_checkpoint",
                    tick_index=tick,
                    expected=None,
                    actual=act,
                ),
            )
        if act is None:
            return ReplayDiffResult(
                ok=False,
                checked_count=checked_count,
                failure=ReplayDiffFailure(
                    kind="missing_checkpoint",
                    tick_index=tick,
                    expected=exp,
                    actual=None,
                ),
            )

        if checkpoint_deepdiff(exp, act) is None:
            continue

        return ReplayDiffResult(
            ok=False,
            checked_count=checked_count,
            failure=ReplayDiffFailure(
                kind="state_mismatch",
                tick_index=tick,
                expected=exp,
                actual=act,
            ),
        )

    return ReplayDiffResult(
        ok=True,
        checked_count=checked_count,
        failure=None,
    )
