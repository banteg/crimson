from __future__ import annotations

from .canonical_channels import (
    EntitySamplesSnapshot,
    ReplayStepSnapshot,
    RngStreamRow,
    SimStateSnapshot,
    TimingSampleRow,
)
from .channel_helpers import ENTITY_SAMPLE_KINDS, EntitySampleRow, entity_rows
from .payloads import BuiltinObject, BuiltinRows, to_builtin_object, to_builtin_value
from .strict_compare import strict_mismatch_payload


def _rng_stream_row_payload(row: RngStreamRow, *, field: str) -> BuiltinObject:
    payload = to_builtin_object(
        {
            "tick_call_index": row.tick_call_index,
            "value_15": row.value_15,
            "state_before_u32": row.state_before_u32,
            "state_after_u32": row.state_after_u32,
            "caller": row.caller,
            "caller_hex": (
                None if row.caller is None else f"0x{row.caller:08x}"
            ),
        },
        field=field,
    )
    return payload


def compare_rng_stream(expected_rows: list[RngStreamRow], actual_rows: list[RngStreamRow]) -> tuple[bool, BuiltinObject | None]:
    exp_behavior = [
        (
            row.tick_call_index,
            row.value_15,
            row.state_before_u32,
            row.state_after_u32,
        )
        for row in expected_rows
    ]
    act_behavior = [
        (
            row.tick_call_index,
            row.value_15,
            row.state_before_u32,
            row.state_after_u32,
        )
        for row in actual_rows
    ]
    max_prefix = min(len(exp_behavior), len(act_behavior))
    behavior_prefix = 0
    while behavior_prefix < max_prefix and exp_behavior[behavior_prefix] == act_behavior[behavior_prefix]:
        behavior_prefix += 1
    caller_prefix = 0
    while (
        caller_prefix < max_prefix
        and expected_rows[caller_prefix].caller == actual_rows[caller_prefix].caller
    ):
        caller_prefix += 1
    behavior_ok = behavior_prefix == len(exp_behavior) == len(act_behavior)
    attribution_ok = behavior_ok and caller_prefix == len(expected_rows) == len(actual_rows)
    if behavior_ok and attribution_ok:
        return True, None
    detail = to_builtin_object(
        {
            "behavior_ok": behavior_ok,
            "caller_attribution_ok": attribution_ok,
            "classification": ("caller_attribution_only" if behavior_ok else "rng_behavior"),
            "behavior_prefix_match_len": behavior_prefix,
            "caller_prefix_match_len": caller_prefix,
            "expected_calls": len(exp_behavior),
            "actual_calls": len(act_behavior),
            "missing_tail": max(0, len(exp_behavior) - len(act_behavior)),
            "extra_tail": max(0, len(act_behavior) - len(exp_behavior)),
        },
        field="rng_stream.diff",
    )
    mismatch_index = caller_prefix if behavior_ok else behavior_prefix
    if mismatch_index < len(expected_rows):
        detail["expected_first_mismatch"] = _rng_stream_row_payload(
            expected_rows[mismatch_index],
            field="rng_stream.expected",
        )
    if mismatch_index < len(actual_rows):
        detail["actual_first_mismatch"] = _rng_stream_row_payload(
            actual_rows[mismatch_index],
            field="rng_stream.actual",
        )
    return behavior_ok, detail


def compare_replay_step(
    expected_obj: ReplayStepSnapshot,
    actual_obj: ReplayStepSnapshot,
) -> tuple[bool, BuiltinObject | None]:
    payload, diff_count, pretty = strict_mismatch_payload(expected_obj, actual_obj, root_path="replay_step")
    if int(diff_count) == 0:
        return True, None
    return False, to_builtin_object(
        {
            "diff_count": int(diff_count),
            "mismatches": payload,
            "pretty": pretty,
        },
        field="replay_step.diff",
    )


def compare_sim_state(
    expected_obj: SimStateSnapshot,
    actual_obj: SimStateSnapshot,
) -> tuple[bool, BuiltinObject | None]:
    payload, diff_count, pretty = strict_mismatch_payload(expected_obj, actual_obj, root_path="sim_state")
    if int(diff_count) == 0:
        return True, None
    return False, to_builtin_object(
        {
            "diff_count": int(diff_count),
            "mismatches": payload,
            "pretty": pretty,
        },
        field="sim_state.diff",
    )


def compare_timing_samples(
    expected_rows: list[TimingSampleRow],
    actual_rows: list[TimingSampleRow],
) -> tuple[bool, BuiltinObject | None]:
    payload, diff_count, pretty = strict_mismatch_payload(
        expected_rows,
        actual_rows,
        root_path="timing_samples",
    )
    if int(diff_count) == 0:
        return True, None
    return False, to_builtin_object(
        {
            "diff_count": int(diff_count),
            "mismatches": payload,
            "pretty": pretty,
        },
        field="timing_samples.diff",
    )


def _rows_by_uid(rows: list[EntitySampleRow]) -> tuple[dict[int, EntitySampleRow], int, list[int]]:
    by_uid: dict[int, EntitySampleRow] = {}
    duplicate_uids: list[int] = []
    for row in rows:
        uid = int(row.uid)
        if uid in by_uid:
            duplicate_uids.append(uid)
        by_uid[uid] = row
    return by_uid, len(rows), duplicate_uids


def compare_entity_samples(
    expected_obj: EntitySamplesSnapshot,
    actual_obj: EntitySamplesSnapshot,
) -> tuple[bool, BuiltinObject | None]:
    detail: BuiltinObject = {}
    row_diffs: BuiltinRows = []
    for kind in ENTITY_SAMPLE_KINDS:
        exp_map, exp_total, exp_dupes = _rows_by_uid(entity_rows(expected_obj, kind=kind))
        act_map, act_total, act_dupes = _rows_by_uid(entity_rows(actual_obj, kind=kind))
        if exp_total != act_total:
            detail[f"{kind}_count"] = {"expected": exp_total, "actual": act_total}
        if exp_dupes or act_dupes:
            detail[f"{kind}_duplicate_uids"] = {
                "expected": exp_dupes,
                "actual": act_dupes,
            }

        missing = sorted(uid for uid in exp_map if uid not in act_map)
        extra = sorted(uid for uid in act_map if uid not in exp_map)
        if missing or extra:
            detail[f"{kind}_uids"] = {
                "missing": missing,
                "extra": extra,
            }

        for uid in sorted(set(exp_map) & set(act_map)):
            expected_row = exp_map[uid]
            actual_row = act_map[uid]
            row_path = f"entity_samples.{kind}[uid={uid}]"
            payload, diff_count, pretty = strict_mismatch_payload(
                expected_row,
                actual_row,
                root_path=row_path,
            )
            if int(diff_count) == 0:
                continue
            row_diffs.append(
                {
                    "path": row_path,
                    "diff_count": int(diff_count),
                    "mismatches": payload,
                    "pretty": pretty,
                },
            )

    if row_diffs:
        detail["row_diffs"] = to_builtin_value(row_diffs, field="entity_samples.row_diffs")
    return (len(detail) == 0), (None if len(detail) == 0 else detail)
