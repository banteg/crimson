from __future__ import annotations

import msgspec

from .canonical_channels import (
    CreatureEntitySample,
    EntitySamplesSnapshot,
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
    exp_keys = [
        (
            row.tick_call_index,
            row.value_15,
            row.state_before_u32,
            row.state_after_u32,
            row.caller,
        )
        for row in expected_rows
    ]
    act_keys = [
        (
            row.tick_call_index,
            row.value_15,
            row.state_before_u32,
            row.state_after_u32,
            row.caller,
        )
        for row in actual_rows
    ]
    max_prefix = min(len(exp_keys), len(act_keys))
    prefix = 0
    while prefix < max_prefix and exp_keys[prefix] == act_keys[prefix]:
        prefix += 1
    if prefix == len(exp_keys) == len(act_keys):
        return True, None
    detail = to_builtin_object(
        {
            "prefix_match_len": prefix,
            "expected_calls": len(exp_keys),
            "actual_calls": len(act_keys),
            "missing_tail": max(0, len(exp_keys) - len(act_keys)),
            "extra_tail": max(0, len(act_keys) - len(exp_keys)),
        },
        field="rng_stream.diff",
    )
    if prefix < len(expected_rows):
        detail["expected_first_mismatch"] = _rng_stream_row_payload(
            expected_rows[prefix],
            field="rng_stream.expected",
        )
    if prefix < len(actual_rows):
        detail["actual_first_mismatch"] = _rng_stream_row_payload(
            actual_rows[prefix],
            field="rng_stream.actual",
        )
    return False, detail


def compare_sim_state(
    expected_obj: SimStateSnapshot,
    actual_obj: SimStateSnapshot,
) -> tuple[bool, BuiltinObject | None]:
    if expected_obj == actual_obj:
        return True, None
    payload, diff_count, pretty = strict_mismatch_payload(expected_obj, actual_obj, root_path="sim_state")
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
    if expected_rows == actual_rows:
        return True, None
    payload, diff_count, pretty = strict_mismatch_payload(
        expected_rows,
        actual_rows,
        root_path="timing_samples",
    )
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


def _mask_absent_optional_channels(
    expected_row: EntitySampleRow,
    actual_row: EntitySampleRow,
) -> tuple[EntitySampleRow, EntitySampleRow]:
    """Optional creature movement channels only compare when both traces
    recorded them (capture v14+); older traces carry None."""

    if not (isinstance(expected_row, CreatureEntitySample) and isinstance(actual_row, CreatureEntitySample)):
        return expected_row, actual_row
    if expected_row.vel is None or actual_row.vel is None:
        expected_row = msgspec.structs.replace(expected_row, vel=None)
        actual_row = msgspec.structs.replace(actual_row, vel=None)
    if expected_row.move_speed is None or actual_row.move_speed is None:
        expected_row = msgspec.structs.replace(expected_row, move_speed=None)
        actual_row = msgspec.structs.replace(actual_row, move_speed=None)
    return expected_row, actual_row


def compare_entity_samples(
    expected_obj: EntitySamplesSnapshot,
    actual_obj: EntitySamplesSnapshot,
) -> tuple[bool, BuiltinObject | None]:
    if expected_obj == actual_obj:
        return True, None

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
            expected_row, actual_row = _mask_absent_optional_channels(expected_row, actual_row)
            if expected_row == actual_row:
                continue
            row_path = f"entity_samples.{kind}[uid={uid}]"
            payload, diff_count, pretty = strict_mismatch_payload(
                expected_row,
                actual_row,
                root_path=row_path,
            )
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
