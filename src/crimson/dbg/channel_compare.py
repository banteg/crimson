from __future__ import annotations

from .channel_helpers import ENTITY_SAMPLE_KINDS, as_object_dict, as_object_list, rng_row_key

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

    expected_map = as_object_dict(expected)
    actual_map = as_object_dict(actual)
    if expected_map is not None or actual_map is not None:
        if expected_map is None or actual_map is None:
            _record_diff(
                out=out,
                path=path,
                expected=expected,
                actual=actual,
                max_rows=max_rows,
            )
            return
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

    expected_list = expected if isinstance(expected, list) else None
    actual_list = actual if isinstance(actual, list) else None
    if expected_list is not None or actual_list is not None:
        if expected_list is None or actual_list is None:
            _record_diff(
                out=out,
                path=path,
                expected=expected,
                actual=actual,
                max_rows=max_rows,
            )
            return
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

    if expected != actual:
        _record_diff(
            out=out,
            path=path,
            expected=expected,
            actual=actual,
            max_rows=max_rows,
        )


def compare_rng_stream(expected_rows: list[object], actual_rows: list[object]) -> tuple[bool, dict[str, object] | None]:
    exp_keys = [rng_row_key(row) for row in expected_rows]
    act_keys = [rng_row_key(row) for row in actual_rows]
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
        detail["expected_first_mismatch"] = expected_rows[prefix]
    if prefix < len(actual_rows):
        detail["actual_first_mismatch"] = actual_rows[prefix]
    return False, detail


def compare_sim_state(
    expected_obj: object,
    actual_obj: object,
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    expected = as_object_dict(expected_obj)
    actual = as_object_dict(actual_obj)
    if expected is None or actual is None:
        return False, {"error": "sim_state must be objects in both traces"}
    if expected == actual:
        return True, None
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


def _rows_by_uid(
    samples_obj: object,
    *,
    kind: str,
) -> tuple[dict[int, dict[str, object]], int, list[int], int]:
    samples = as_object_dict(samples_obj)
    if samples is None:
        return {}, 0, [], 0
    rows = as_object_list(samples.get(kind))
    by_uid: dict[int, dict[str, object]] = {}
    duplicate_uids: list[int] = []
    invalid_rows = 0
    for row in rows:
        mapped = as_object_dict(row)
        if mapped is None:
            invalid_rows += 1
            continue
        uid_obj = mapped.get("uid")
        if not isinstance(uid_obj, int) or isinstance(uid_obj, bool):
            invalid_rows += 1
            continue
        uid = int(uid_obj)
        if uid in by_uid:
            duplicate_uids.append(uid)
        by_uid[uid] = mapped
    return by_uid, len(rows), duplicate_uids, invalid_rows


def compare_entity_samples(
    expected_obj: object,
    actual_obj: object,
    *,
    max_diff_rows: int = _DEFAULT_MAX_DIFF_ROWS,
) -> tuple[bool, dict[str, object] | None]:
    expected = as_object_dict(expected_obj)
    actual = as_object_dict(actual_obj)
    if expected is None or actual is None:
        return False, {"error": "entity_samples must be objects in both traces"}
    if expected == actual:
        return True, None

    detail: dict[str, object] = {}
    diffs: list[dict[str, object]] = []
    for kind in ENTITY_SAMPLE_KINDS:
        exp_map, exp_total, exp_dupes, exp_invalid = _rows_by_uid(expected, kind=kind)
        act_map, act_total, act_dupes, act_invalid = _rows_by_uid(actual, kind=kind)
        if exp_total != act_total:
            detail[f"{kind}_count"] = {"expected": exp_total, "actual": act_total}
        if exp_invalid or act_invalid:
            detail[f"{kind}_invalid_rows"] = {"expected": exp_invalid, "actual": act_invalid}
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
