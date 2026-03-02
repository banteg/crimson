# type: ignore[invalid-assignment,invalid-argument-type,no-matching-overload]
from __future__ import annotations

import json
import math
import struct
from collections.abc import Iterable, Sequence

import msgspec
from deepdiff import DeepDiff

from ..replay.checkpoints import ReplayCheckpoint

DEFAULT_RNG_MARK_ORDER: tuple[str, ...] = (
    "before_world_step",
    "gw_begin",
    "gw_after_weapon_refresh",
    "gw_after_perks_rebuild",
    "gw_after_time_scale",
    "ws_begin",
    "ws_after_perk_effects",
    "ws_after_effects_update",
    "ws_after_creatures",
    "ws_after_projectiles",
    "ws_after_secondary_projectiles",
    "ws_after_particles_update",
    "ws_after_sprite_effects",
    "ws_after_particles",
    "ws_after_player_update_p0",
    "ws_after_player_update",
    "ws_after_bonus_update",
    "ws_after_progression",
    "ws_after_sfx_queue_merge",
    "ws_after_player_damage_sfx",
    "ws_after_sfx",
    "after_world_step",
    "after_stage_spawns",
    "after_wave_spawns",
    "after_rush_spawns",
)

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


class ReplayDiffFailure(msgspec.Struct, frozen=True):
    kind: str
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None = None
    first_rng_mark: str | None = None


class ReplayDiffResult(msgspec.Struct, frozen=True):
    ok: bool
    checked_count: int
    first_rng_only_tick: int | None = None
    failure: ReplayDiffFailure | None = None


class CheckpointDeepDiff(msgspec.Struct, frozen=True):
    payload: dict[str, object]
    pretty: str
    diff_count: int


def _checkpoint_to_obj(
    checkpoint: ReplayCheckpoint,
    *,
    include_hash_fields: bool,
    include_rng_fields: bool,
) -> dict[str, object]:
    obj = msgspec.to_builtins(checkpoint)
    if not include_hash_fields:
        for key in ("state_hash", "command_hash"):
            obj.pop(key, None)
    if not include_rng_fields:
        for key in ("rng_state", "rng_marks"):
            obj.pop(key, None)
    return obj


def _normalize_checkpoint_for_diff(
    checkpoint: ReplayCheckpoint,
    *,
    include_hash_fields: bool,
    include_rng_fields: bool,
    elapsed_base: int | None,
) -> ReplayCheckpoint:
    out = checkpoint
    if not include_hash_fields:
        out = msgspec.structs.replace(out, state_hash="", command_hash="")
    if not include_rng_fields:
        out = msgspec.structs.replace(out, rng_state=0, rng_marks={})
    if elapsed_base is not None and int(out.elapsed_ms) >= 0:
        out = msgspec.structs.replace(out, elapsed_ms=int(out.elapsed_ms) - int(elapsed_base))
    return out


def _is_numeric_value(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _ordered_float32_bits(bits: int) -> int:
    if bits & 0x80000000:
        return 0xFFFFFFFF - bits
    return bits + 0x80000000


def _float32_ulp_distance(expected_value: float, actual_value: float) -> int | None:
    if not math.isfinite(expected_value) or not math.isfinite(actual_value):
        return 0 if expected_value == actual_value else None
    try:
        expected_bits = struct.unpack(">I", struct.pack(">f", float(expected_value)))[0]
        actual_bits = struct.unpack(">I", struct.pack(">f", float(actual_value)))[0]
    except (OverflowError, ValueError):
        return None
    return abs(_ordered_float32_bits(expected_bits) - _ordered_float32_bits(actual_bits))


def _numbers_match_tolerance(
    expected_value: object,
    actual_value: object,
    *,
    float_abs_tol: float,
    float_ulp_tol: int,
) -> bool:
    if not _is_numeric_value(expected_value) or not _is_numeric_value(actual_value):
        return False
    expected_float = float(expected_value)
    actual_float = float(actual_value)
    if math.isnan(expected_float) and math.isnan(actual_float):
        return True
    if expected_float == actual_float:
        return True
    abs_tol = max(0.0, float(float_abs_tol))
    if math.isclose(expected_float, actual_float, rel_tol=0.0, abs_tol=abs_tol):
        return True
    max_ulp = max(0, int(float_ulp_tol))
    if max_ulp <= 0:
        return False
    ulp_distance = _float32_ulp_distance(expected_float, actual_float)
    return ulp_distance is not None and int(ulp_distance) <= max_ulp


def _path_matches_ignored_prefix(path: str, prefixes: Sequence[str]) -> bool:
    for prefix in prefixes:
        target = f"root.{prefix}"
        if path == target:
            return True
        if path.startswith(f"{target}."):
            return True
        if path.startswith(f"{target}["):
            return True
    return False


def _is_value_change_payload_category(category: str) -> bool:
    return category in {"type_changes", "values_changed"}


def _to_jsonable(value: object) -> object:
    match value:
        case dict() as mapping:
            return {str(k): _to_jsonable(v) for k, v in mapping.items()}
        case list() as items:
            return [_to_jsonable(v) for v in items]
        case tuple() as items:
            return [_to_jsonable(v) for v in items]
        case set() as items:
            return [_to_jsonable(v) for v in sorted(items, key=repr)]
        case type() as t:
            return t.__name__
        case _:
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray, dict)):
                return [_to_jsonable(v) for v in value]
            return value


def _iter_paths(category_payload: object) -> list[str]:
    match category_payload:
        case dict() as mapping:
            return sorted((str(k) for k in mapping.keys()), key=str)
        case _:
            if isinstance(category_payload, Iterable) and not isinstance(category_payload, (str, bytes, bytearray, dict)):
                return sorted((str(v) for v in category_payload), key=str)
            return []


def _normalize_deepdiff_payload(
    raw_payload: dict[str, object],
    *,
    ignore_field_prefixes: Sequence[str],
    max_diffs: int | None,
    float_abs_tol: float,
    float_ulp_tol: int,
) -> tuple[dict[str, object], int]:
    out: dict[str, object] = {}
    total = 0
    limit = (None if max_diffs is None else max(1, int(max_diffs)))

    for category in _DEEPDIFF_CATEGORY_ORDER:
        if limit is not None and total >= limit:
            break
        payload = raw_payload.get(category)
        if payload is None:
            continue

        match payload:
            case dict() as mapping:
                category_out: dict[str, object] = {}
                for path in sorted((str(k) for k in mapping.keys()), key=str):
                    if limit is not None and total >= limit:
                        break
                    if _path_matches_ignored_prefix(path, ignore_field_prefixes):
                        continue
                    row = mapping[path]
                    if _is_value_change_payload_category(category) and isinstance(row, dict):
                        old_value = row.get("old_value", "<missing>")
                        new_value = row.get("new_value", "<missing>")
                        if _numbers_match_tolerance(
                            old_value,
                            new_value,
                            float_abs_tol=float_abs_tol,
                            float_ulp_tol=float_ulp_tol,
                        ):
                            continue
                    category_out[path] = _to_jsonable(row)
                    total += 1
                if category_out:
                    out[category] = category_out
            case _:
                paths = _iter_paths(payload)
                if not paths:
                    continue
                category_out_list: list[str] = []
                for path in paths:
                    if limit is not None and total >= limit:
                        break
                    if _path_matches_ignored_prefix(path, ignore_field_prefixes):
                        continue
                    category_out_list.append(path)
                    total += 1
                if category_out_list:
                    out[category] = category_out_list

    return out, total


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    *,
    include_hash_fields: bool = True,
    include_rng_fields: bool = True,
    ignore_field_prefixes: Sequence[str] = (),
    elapsed_baseline: tuple[int, int] | None = None,
    max_diffs: int | None = None,
    float_abs_tol: float = 0.0001,
    float_ulp_tol: int = 0,
) -> CheckpointDeepDiff | None:
    exp_base = None
    act_base = None
    if elapsed_baseline is not None:
        exp_base, act_base = elapsed_baseline

    expected_checkpoint = _normalize_checkpoint_for_diff(
        expected,
        include_hash_fields=bool(include_hash_fields),
        include_rng_fields=bool(include_rng_fields),
        elapsed_base=exp_base,
    )
    actual_checkpoint = _normalize_checkpoint_for_diff(
        actual,
        include_hash_fields=bool(include_hash_fields),
        include_rng_fields=bool(include_rng_fields),
        elapsed_base=act_base,
    )

    deep = DeepDiff(
        expected_checkpoint,
        actual_checkpoint,
        ignore_order=False,
        verbose_level=2,
        math_epsilon=max(0.0, float(float_abs_tol)),
    )

    raw_payload = dict(deep.to_dict())
    payload, diff_count = _normalize_deepdiff_payload(
        raw_payload,
        ignore_field_prefixes=tuple(str(prefix) for prefix in ignore_field_prefixes),
        max_diffs=max_diffs,
        float_abs_tol=float_abs_tol,
        float_ulp_tol=float_ulp_tol,
    )
    if int(diff_count) <= 0:
        return None

    return CheckpointDeepDiff(
        payload=payload,
        pretty=json.dumps(payload, sort_keys=True, indent=2, default=repr),
        diff_count=int(diff_count),
    )


def compare_checkpoints(
    expected: Sequence[ReplayCheckpoint],
    actual: Sequence[ReplayCheckpoint],
    *,
    rng_mark_order: Sequence[str] = DEFAULT_RNG_MARK_ORDER,
) -> ReplayDiffResult:
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    first_rng_only_tick: int | None = None
    checked_count = 0

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
            )

        if str(exp.command_hash) and str(exp.command_hash) != str(act.command_hash):
            return ReplayDiffResult(
                ok=False,
                checked_count=checked_count,
                first_rng_only_tick=first_rng_only_tick,
                failure=ReplayDiffFailure(
                    kind="command_mismatch",
                    tick_index=tick,
                    expected=exp,
                    actual=act,
                ),
            )

        if str(exp.state_hash) == str(act.state_hash):
            continue

        exp_no_rng = _checkpoint_to_obj(exp, include_hash_fields=False, include_rng_fields=False)
        act_no_rng = _checkpoint_to_obj(act, include_hash_fields=False, include_rng_fields=False)
        if exp_no_rng == act_no_rng:
            if first_rng_only_tick is None:
                first_rng_only_tick = tick
            continue

        mark_keys = sorted({*exp.rng_marks.keys(), *act.rng_marks.keys()})
        mark_mismatch: list[str] = []
        for key in mark_keys:
            if key in exp.rng_marks:
                exp_mark = int(exp.rng_marks[key])
            else:
                exp_mark = -1
            if key in act.rng_marks:
                act_mark = int(act.rng_marks[key])
            else:
                act_mark = -1
            if exp_mark != act_mark:
                mark_mismatch.append(key)
        first_mark = next((key for key in rng_mark_order if key in mark_mismatch), mark_mismatch[0] if mark_mismatch else None)
        return ReplayDiffResult(
            ok=False,
            checked_count=checked_count,
            first_rng_only_tick=first_rng_only_tick,
            failure=ReplayDiffFailure(
                kind="state_mismatch",
                tick_index=tick,
                expected=exp,
                actual=act,
                first_rng_mark=first_mark,
            ),
        )

    return ReplayDiffResult(
        ok=True,
        checked_count=checked_count,
        first_rng_only_tick=first_rng_only_tick,
        failure=None,
    )
