# type: ignore[invalid-assignment,invalid-argument-type,no-matching-overload]
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import cast

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


def _normalize_deepdiff_payload(
    raw_payload: dict[str, object],
    *,
    ignore_field_prefixes: Sequence[str],
    max_diffs: int | None,
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
                for key in sorted(mapping.keys(), key=str):
                    if not isinstance(key, str):
                        raise TypeError(f"deepdiff dict category {category} had non-string key")
                    path = str(key)
                    if limit is not None and total >= limit:
                        break
                    if _path_matches_ignored_prefix(path, ignore_field_prefixes):
                        continue
                    row = mapping[key]
                    category_out[path] = row
                    total += 1
                if category_out:
                    out[category] = category_out
            case list() as paths:
                category_out_list: list[str] = []
                for path in paths:
                    if limit is not None and total >= limit:
                        break
                    if not isinstance(path, str):
                        raise TypeError(f"deepdiff list category {category} had non-string path value")
                    path_text = str(path)
                    if _path_matches_ignored_prefix(path_text, ignore_field_prefixes):
                        continue
                    category_out_list.append(path_text)
                    total += 1
                if category_out_list:
                    out[category] = category_out_list
            case _:
                raise TypeError(f"unsupported deepdiff category payload for {category}: {type(payload).__name__}")

    return out, total


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    *,
    ignore_field_prefixes: Sequence[str] = (),
    max_diffs: int | None = None,
    float_abs_tol: float = 0.0,
) -> CheckpointDeepDiff | None:
    deep = DeepDiff(
        expected,
        actual,
        ignore_order=False,
        verbose_level=2,
        math_epsilon=max(0.0, float(float_abs_tol)),
    )

    raw_json = json.loads(str(deep.to_json()))
    if isinstance(raw_json, dict):
        raw_payload = cast("dict[str, object]", raw_json)
    else:
        raise TypeError("deepdiff payload must decode to object")
    payload, diff_count = _normalize_deepdiff_payload(
        raw_payload,
        ignore_field_prefixes=tuple(str(prefix) for prefix in ignore_field_prefixes),
        max_diffs=max_diffs,
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
