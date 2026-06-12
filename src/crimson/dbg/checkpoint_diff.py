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
    include_hit_head: bool = True,
    mask_capture_placeholder_fields: bool = False,
) -> BuiltinObject:
    obj = to_builtin_object(checkpoint, field="checkpoint")
    if not include_rng_fields:
        for key in ("rng_state",):
            obj.pop(key, None)
    if not include_hit_head:
        events = obj.get("events")
        if isinstance(events, dict):
            events.pop("hit_head", None)
    if mask_capture_placeholder_fields:
        # The frida capture's creature_handle_death hook records no reward/xp
        # arguments, so its deaths carry reward_value=0, xp_awarded=0,
        # owner_id=-1 placeholders; mask those fields on both sides so only
        # the structural death record (creature_index, type_id) is compared.
        deaths = obj.get("deaths")
        if isinstance(deaths, list):
            for entry in deaths:
                if isinstance(entry, dict):
                    entry.pop("reward_value", None)
                    entry.pop("xp_awarded", None)
                    entry.pop("owner_id", None)
    return obj


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    *,
    include_rng_fields: bool = True,
    capture_compare: bool = False,
) -> CheckpointDeepDiff | None:
    # `capture_compare` is for diffing against frida_original traces, which
    # record no hit_head channel and only placeholder death reward fields.
    expected_obj = _checkpoint_to_obj(
        expected,
        include_rng_fields=bool(include_rng_fields),
        include_hit_head=not capture_compare,
        mask_capture_placeholder_fields=bool(capture_compare),
    )
    actual_obj = _checkpoint_to_obj(
        actual,
        include_rng_fields=bool(include_rng_fields),
        include_hit_head=not capture_compare,
        mask_capture_placeholder_fields=bool(capture_compare),
    )
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

        include_hit_head = bool(exp.events.hit_head) and bool(act.events.hit_head)
        exp_no_rng = _checkpoint_to_obj(exp, include_rng_fields=False, include_hit_head=include_hit_head)
        act_no_rng = _checkpoint_to_obj(act, include_rng_fields=False, include_hit_head=include_hit_head)
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
