# type: ignore[invalid-assignment,invalid-argument-type,no-matching-overload]
from __future__ import annotations

import math
from collections.abc import Sequence

import msgspec

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


class ReplayFieldDiff(msgspec.Struct, frozen=True):
    field: str
    expected: object
    actual: object


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


def _int_is_unknown(value: object) -> bool:
    match value:
        case int() as int_value:
            return int(int_value) < 0
        case _:
            return False


def normalize_unknown_fields(exp: dict[str, object], act: dict[str, object]) -> None:
    for key in ("elapsed_ms", "score_xp", "kills", "creature_count", "perk_pending"):
        if _int_is_unknown((exp[key] if key in exp else None)):
            exp[key] = (act[key] if key in act else None)

    exp_bonus = (exp["bonus_timers"] if "bonus_timers" in exp else None)
    act_bonus = (act["bonus_timers"] if "bonus_timers" in act else None)
    match (exp_bonus, act_bonus):
        case (dict() as exp_bonus_map, dict() as act_bonus_map):
            for key, value in list(exp_bonus_map.items()):
                if _int_is_unknown(value):
                    exp_bonus_map[key] = (act_bonus_map[key] if key in act_bonus_map else None)
        case _:
            pass

    exp_perk = (exp["perk"] if "perk" in exp else None)
    act_perk = (act["perk"] if "perk" in act else None)
    match (exp_perk, act_perk):
        case (dict() as exp_perk_map, dict() as act_perk_map):
            if _int_is_unknown((exp_perk_map["pending_count"] if "pending_count" in exp_perk_map else None)):
                exp["perk"] = act_perk_map
        case _:
            pass

    exp_deaths = (exp["deaths"] if "deaths" in exp else None)
    match exp_deaths:
        case [dict() as row]:
            is_unknown_death = (
                _int_is_unknown((row["creature_index"] if "creature_index" in row else None))
                and _int_is_unknown((row["type_id"] if "type_id" in row else None))
                and _int_is_unknown((row["xp_awarded"] if "xp_awarded" in row else None))
            )
            if is_unknown_death:
                exp["deaths"] = (act["deaths"] if "deaths" in act else None)
        case _:
            pass


def _path_join(path: str, suffix: str) -> str:
    if not path:
        return suffix
    return f"{path}.{suffix}"


def _values_equal(expected: object, actual: object, *, float_abs_tol: float) -> bool:
    abs_tol = max(0.0, float(float_abs_tol)) + 1e-12
    match (expected, actual):
        case (float() as exp_float, int() | float() as act_num):
            return math.isclose(float(exp_float), float(act_num), rel_tol=0.0, abs_tol=abs_tol)
        case (int() | float() as exp_num, float() as act_float):
            return math.isclose(float(exp_num), float(act_float), rel_tol=0.0, abs_tol=abs_tol)
        case _:
            return expected == actual


def _collect_field_diffs(
    *,
    path: str,
    expected: object,
    actual: object,
    out: list[ReplayFieldDiff],
    max_diffs: int | None,
    float_abs_tol: float,
) -> None:
    if max_diffs is not None and len(out) >= int(max_diffs):
        return

    match (expected, actual):
        case (dict() as expected_map, dict() as actual_map):
            keys = sorted({*expected_map.keys(), *actual_map.keys()})
            for key in keys:
                key_str = str(key)
                has_exp = key in expected_map or key_str in expected_map
                has_act = key in actual_map or key_str in actual_map
                if key_str in expected_map:
                    exp_value = expected_map[key_str]
                elif key in expected_map:
                    exp_value = expected_map[key]
                else:
                    exp_value = None
                if key_str in actual_map:
                    act_value = actual_map[key_str]
                elif key in actual_map:
                    act_value = actual_map[key]
                else:
                    act_value = None
                if not has_exp or not has_act:
                    out.append(
                        ReplayFieldDiff(
                            field=_path_join(path, key_str),
                            expected=exp_value if has_exp else "<missing>",
                            actual=act_value if has_act else "<missing>",
                        ),
                    )
                    if max_diffs is not None and len(out) >= int(max_diffs):
                        return
                    continue
                _collect_field_diffs(
                    path=_path_join(path, key_str),
                    expected=exp_value,
                    actual=act_value,
                    out=out,
                    max_diffs=max_diffs,
                    float_abs_tol=float_abs_tol,
                )
                if max_diffs is not None and len(out) >= int(max_diffs):
                    return
            return
        case (list() as expected_list, list() as actual_list):
            if len(expected_list) != len(actual_list):
                out.append(
                    ReplayFieldDiff(
                        field=_path_join(path, "_len"),
                        expected=int(len(expected_list)),
                        actual=int(len(actual_list)),
                    ),
                )
                if max_diffs is not None and len(out) >= int(max_diffs):
                    return
            for idx, (exp_value, act_value) in enumerate(zip(expected_list, actual_list)):
                _collect_field_diffs(
                    path=f"{path}[{idx}]" if path else f"[{idx}]",
                    expected=exp_value,
                    actual=act_value,
                    out=out,
                    max_diffs=max_diffs,
                    float_abs_tol=float_abs_tol,
                )
                if max_diffs is not None and len(out) >= int(max_diffs):
                    return
            return
        case _:
            pass

    # Capture checkpoints quantize global bonus timers to integer ms in JS.
    # A one-ms jitter can appear from float edge cases and self-heal on the
    # next tick without affecting deterministic simulation behavior.
    match (expected, actual):
        case (int() as expected_int, int() as actual_int):
            if path.startswith("bonus_timers."):
                timer_key = path.removeprefix("bonus_timers.")
                if timer_key in {"2", "4", "6", "9", "11"}:
                    if int(expected_int) > 0 and int(actual_int) > 0 and abs(int(expected_int) - int(actual_int)) <= 1:
                        return
        case _:
            pass

    if not _values_equal(expected, actual, float_abs_tol=float_abs_tol):
        out.append(
            ReplayFieldDiff(
                field=path or "<root>",
                expected=expected,
                actual=actual,
            ),
        )


def checkpoint_field_diffs(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
    *,
    include_hash_fields: bool = True,
    include_rng_fields: bool = True,
    normalize_unknown: bool = True,
    unknown_events_wildcard: bool = True,
    elapsed_baseline: tuple[int, int] | None = None,
    max_diffs: int | None = None,
    float_abs_tol: float = 0.0001,
) -> list[ReplayFieldDiff]:
    exp_obj = _checkpoint_to_obj(
        expected,
        include_hash_fields=bool(include_hash_fields),
        include_rng_fields=bool(include_rng_fields),
    )
    act_obj = _checkpoint_to_obj(
        actual,
        include_hash_fields=bool(include_hash_fields),
        include_rng_fields=bool(include_rng_fields),
    )

    if elapsed_baseline is not None:
        exp_base, act_base = elapsed_baseline
        exp_elapsed = (exp_obj["elapsed_ms"] if "elapsed_ms" in exp_obj else None)
        act_elapsed = (act_obj["elapsed_ms"] if "elapsed_ms" in act_obj else None)
        match (exp_elapsed, act_elapsed):
            case (int() as exp_elapsed_int, int() as act_elapsed_int):
                if int(exp_elapsed_int) >= 0 and int(act_elapsed_int) >= 0:
                    exp_obj["elapsed_ms"] = int(exp_elapsed_int) - int(exp_base)
                    act_obj["elapsed_ms"] = int(act_elapsed_int) - int(act_base)
            case _:
                pass

    if normalize_unknown:
        normalize_unknown_fields(exp_obj, act_obj)

    # Legacy sidecars (without `events`) store unknown sentinel values.
    if unknown_events_wildcard and int(expected.events.hit_count) < 0:
        exp_obj["events"] = (act_obj["events"] if "events" in act_obj else None)

    diffs: list[ReplayFieldDiff] = []
    _collect_field_diffs(
        path="",
        expected=exp_obj,
        actual=act_obj,
        out=diffs,
        max_diffs=max_diffs,
        float_abs_tol=float_abs_tol,
    )
    return diffs


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
        normalize_unknown_fields(exp_no_rng, act_no_rng)
        # Legacy sidecars (without `events`) store unknown sentinel values.
        if int(exp.events.hit_count) < 0:
            exp_no_rng["events"] = (act_no_rng["events"] if "events" in act_no_rng else None)

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
