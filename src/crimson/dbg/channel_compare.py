from __future__ import annotations

import json
from typing import cast

import msgspec
from deepdiff import DeepDiff

from .canonical_channels import EntitySamplesSnapshot, RngStreamRow, SimStateSnapshot
from .channel_helpers import ENTITY_SAMPLE_KINDS, EntitySampleRow, entity_rows

_DEFAULT_MAX_DIFF_ROWS = 16
_DEEPDIFF_CATEGORY_ORDER: tuple[str, ...] = (
    "type_changes",
    "values_changed",
    "dictionary_item_removed",
    "iterable_item_removed",
    "set_item_removed",
    "dictionary_item_added",
    "iterable_item_added",
    "set_item_added",
)


def _to_builtin_obj(value: object) -> dict[str, object]:
    return cast("dict[str, object]", msgspec.to_builtins(value))


def _deepdiff_payload(
    expected: object,
    actual: object,
    *,
    max_rows: int,
) -> tuple[dict[str, object], int]:
    deep = DeepDiff(
        expected,
        actual,
        ignore_order=False,
        verbose_level=2,
    )
    raw_json = json.loads(str(deep.to_json()))
    if not isinstance(raw_json, dict):
        raise TypeError("deepdiff payload must decode to object")
    raw = cast("dict[str, object]", raw_json)

    out: dict[str, object] = {}
    total = 0
    limit = max(1, int(max_rows))
    for category in _DEEPDIFF_CATEGORY_ORDER:
        if total >= limit:
            break
        payload = raw.get(category)
        match payload:
            case dict() as mapping:
                keep: dict[str, object] = {}
                for key in sorted(mapping.keys(), key=str):
                    if not isinstance(key, str):
                        raise TypeError(f"deepdiff dict category {category} had non-string key")
                    if total >= limit:
                        break
                    keep[str(key)] = mapping[key]
                    total += 1
                if keep:
                    out[category] = keep
            case list() as rows:
                keep_rows: list[object] = []
                for item in rows:
                    if total >= limit:
                        break
                    keep_rows.append(item)
                    total += 1
                if keep_rows:
                    out[category] = keep_rows
            case _:
                raise TypeError(f"unsupported deepdiff category payload for {category}: {type(payload).__name__}")
    return out, total


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
    expected_obj: SimStateSnapshot,
    actual_obj: SimStateSnapshot,
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    if expected_obj == actual_obj:
        return True, None
    payload, diff_count = _deepdiff_payload(
        expected_obj,
        actual_obj,
        max_rows=max_diff_rows,
    )
    return False, {
        "diff_count": int(diff_count),
        "payload": payload,
        "pretty": json.dumps(payload, sort_keys=True, indent=2),
    }


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
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    if expected_obj == actual_obj:
        return True, None

    detail: dict[str, object] = {}
    row_diffs: list[dict[str, object]] = []
    row_limit = max(1, int(max_diff_rows))
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
            if len(row_diffs) >= row_limit:
                break
            expected_row = exp_map[uid]
            actual_row = act_map[uid]
            if expected_row == actual_row:
                continue
            payload, diff_count = _deepdiff_payload(expected_row, actual_row, max_rows=row_limit)
            row_diffs.append(
                {
                    "path": f"entity_samples.{kind}[uid={uid}]",
                    "diff_count": int(diff_count),
                    "payload": payload,
                    "pretty": json.dumps(payload, sort_keys=True, indent=2),
                },
            )

    if row_diffs:
        detail["row_diffs"] = row_diffs
    return (len(detail) == 0), (None if len(detail) == 0 else detail)
