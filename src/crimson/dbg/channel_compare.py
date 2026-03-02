from __future__ import annotations

from typing import cast

import msgspec

from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot
from .channel_helpers import ENTITY_SAMPLE_KINDS, EntitySampleRow, entity_rows

_DEFAULT_MAX_DIFF_ROWS = 16


def _record_diff(
    *,
    out: list[dict[str, object]],
    path: str,
    expected: object,
    actual: object,
    max_rows: int,
) -> None:
    if len(out) >= int(max_rows):
        return
    out.append(
        {
            "path": str(path),
            "expected": expected,
            "actual": actual,
        },
    )


def _collect_value_diffs(
    *,
    expected: object,
    actual: object,
    path: str,
    out: list[dict[str, object]],
    max_rows: int,
) -> None:
    if len(out) >= int(max_rows):
        return

    match (expected, actual):
        case (dict() as expected_map, dict() as actual_map):
            for key in sorted(set(expected_map) | set(actual_map)):
                if len(out) >= int(max_rows):
                    return
                child_path = f"{path}.{key}"
                if key not in expected_map:
                    _record_diff(
                        out=out,
                        path=child_path,
                        expected=None,
                        actual=actual_map.get(key),
                        max_rows=max_rows,
                    )
                    continue
                if key not in actual_map:
                    _record_diff(
                        out=out,
                        path=child_path,
                        expected=expected_map.get(key),
                        actual=None,
                        max_rows=max_rows,
                    )
                    continue
                _collect_value_diffs(
                    expected=expected_map[key],
                    actual=actual_map[key],
                    path=child_path,
                    out=out,
                    max_rows=max_rows,
                )
            return
        case (dict(), _) | (_, dict()):
            _record_diff(
                out=out,
                path=path,
                expected=expected,
                actual=actual,
                max_rows=max_rows,
            )
            return
        case (list() as expected_list, list() as actual_list):
            if len(expected_list) != len(actual_list):
                _record_diff(
                    out=out,
                    path=f"{path}.length",
                    expected=len(expected_list),
                    actual=len(actual_list),
                    max_rows=max_rows,
                )
            for idx, (exp_value, act_value) in enumerate(zip(expected_list, actual_list, strict=False)):
                if len(out) >= int(max_rows):
                    return
                _collect_value_diffs(
                    expected=exp_value,
                    actual=act_value,
                    path=f"{path}[{idx}]",
                    out=out,
                    max_rows=max_rows,
                )
            return
        case (list(), _) | (_, list()):
            _record_diff(
                out=out,
                path=path,
                expected=expected,
                actual=actual,
                max_rows=max_rows,
            )
            return
        case _:
            if expected != actual:
                _record_diff(
                    out=out,
                    path=path,
                    expected=expected,
                    actual=actual,
                    max_rows=max_rows,
                )


def _to_builtin_obj(value: object) -> dict[str, object]:
    return cast("dict[str, object]", msgspec.to_builtins(value))


def compare_rng_stream(expected_rows: list[RngStreamRow], actual_rows: list[RngStreamRow]) -> tuple[bool, dict[str, object] | None]:
    exp_keys = [
        (
            int(row.tick_call_index),
            int(row.value_15),
            int(row.state_before_u32),
            int(row.state_after_u32),
        )
        for row in expected_rows
    ]
    act_keys = [
        (
            int(row.tick_call_index),
            int(row.value_15),
            int(row.state_before_u32),
            int(row.state_after_u32),
        )
        for row in actual_rows
    ]
    max_prefix = min(len(exp_keys), len(act_keys))
    prefix = 0
    while prefix < max_prefix and exp_keys[prefix] == act_keys[prefix]:
        prefix += 1
    if prefix == len(exp_keys) == len(act_keys):
        return True, None
    detail: dict[str, object] = {
        "prefix_match_len": prefix,
        "expected_calls": len(exp_keys),
        "actual_calls": len(act_keys),
        "missing_tail": max(0, len(exp_keys) - len(act_keys)),
        "extra_tail": max(0, len(act_keys) - len(exp_keys)),
    }
    if prefix < len(expected_rows):
        detail["expected_first_mismatch"] = _to_builtin_obj(expected_rows[prefix])
    if prefix < len(actual_rows):
        detail["actual_first_mismatch"] = _to_builtin_obj(actual_rows[prefix])
    return False, detail


def compare_sim_state(
    expected_obj: SimStateSnapshot | None,
    actual_obj: SimStateSnapshot | None,
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    if expected_obj is None or actual_obj is None:
        return False, {"error": "sim_state must be present in both traces"}
    if expected_obj == actual_obj:
        return True, None
    expected = _to_builtin_obj(expected_obj)
    actual = _to_builtin_obj(actual_obj)
    diffs: list[dict[str, object]] = []
    _collect_value_diffs(
        expected=expected,
        actual=actual,
        path="sim_state",
        out=diffs,
        max_rows=max(1, int(max_diff_rows)),
    )
    return False, {
        "diff_count": len(diffs),
        "first_diffs": diffs,
    }


def _rows_by_uid(rows: list[EntitySampleRow]) -> tuple[dict[int, dict[str, object]], int, list[int]]:
    by_uid: dict[int, dict[str, object]] = {}
    duplicate_uids: list[int] = []
    for row in rows:
        uid = int(row.uid)
        if uid in by_uid:
            duplicate_uids.append(uid)
        by_uid[uid] = _to_builtin_obj(row)
    return by_uid, len(rows), duplicate_uids


def compare_entity_samples(
    expected_obj: EntitySamplesSnapshot | None,
    actual_obj: EntitySamplesSnapshot | None,
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    if expected_obj is None or actual_obj is None:
        return False, {"error": "entity_samples must be present in both traces"}
    if expected_obj == actual_obj:
        return True, None

    detail: dict[str, object] = {}
    diffs: list[dict[str, object]] = []
    for kind in ENTITY_SAMPLE_KINDS:
        exp_map, exp_total, exp_dupes = _rows_by_uid(entity_rows(expected_obj, kind=kind))
        act_map, act_total, act_dupes = _rows_by_uid(entity_rows(actual_obj, kind=kind))
        if exp_total != act_total:
            detail[f"{kind}_count"] = {"expected": exp_total, "actual": act_total}
        if exp_dupes or act_dupes:
            detail[f"{kind}_duplicate_uids"] = {
                "expected": exp_dupes[:8],
                "actual": act_dupes[:8],
            }

        missing = sorted(uid for uid in exp_map if uid not in act_map)
        extra = sorted(uid for uid in act_map if uid not in exp_map)
        if missing or extra:
            detail[f"{kind}_uids"] = {
                "missing": missing[:16],
                "extra": extra[:16],
            }

        for uid in sorted(set(exp_map) & set(act_map)):
            if len(diffs) >= int(max_diff_rows):
                break
            exp_row = exp_map[uid]
            act_row = act_map[uid]
            if exp_row == act_row:
                continue
            _collect_value_diffs(
                expected=exp_row,
                actual=act_row,
                path=f"entity_samples.{kind}[uid={uid}]",
                out=diffs,
                max_rows=max(1, int(max_diff_rows)),
            )

    if diffs:
        detail["first_diffs"] = diffs
    return (len(detail) == 0), (None if len(detail) == 0 else detail)
