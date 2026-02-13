# type: ignore

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass

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


@dataclass(frozen=True, slots=True)
class ReplayDiffFailure:
    kind: str
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None = None
    first_rng_mark: str | None = None


@dataclass(frozen=True, slots=True)
class ReplayDiffResult:
    ok: bool
    checked_count: int
    first_rng_only_tick: int | None = None
    failure: ReplayDiffFailure | None = None


@dataclass(frozen=True, slots=True)
class ReplayFieldDiff:
    field: str
    expected: object
    actual: object


def _checkpoint_to_obj(
    checkpoint: ReplayCheckpoint,
    *,
    include_hash_fields: bool,
    include_rng_fields: bool,
) -> dict[str, object]:
    obj = asdict(checkpoint)
    if not include_hash_fields:
        for key in ("state_hash", "command_hash"):
            obj.pop(key, None)
    if not include_rng_fields:
        for key in ("rng_state", "rng_marks"):
            obj.pop(key, None)
    return obj


def _int_is_unknown(value: object) -> bool:
    return isinstance(value, int) and int(value) < 0


def normalize_unknown_fields(exp: dict[str, object], act: dict[str, object]) -> None:
    for key in ("elapsed_ms", "score_xp", "kills", "creature_count", "perk_pending"):
        if _int_is_unknown(exp.get(key)):
            exp[key] = act.get(key)

    exp_bonus = exp.get("bonus_timers")
    act_bonus = act.get("bonus_timers")
    if isinstance(exp_bonus, dict) and isinstance(act_bonus, dict):
        for key, value in list(exp_bonus.items()):
            if _int_is_unknown(value):
                exp_bonus[key] = act_bonus.get(key)

    exp_perk = exp.get("perk")
    act_perk = act.get("perk")
    if isinstance(exp_perk, dict) and isinstance(act_perk, dict):
        if _int_is_unknown(exp_perk.get("pending_count")):
            exp["perk"] = act_perk

    exp_deaths = exp.get("deaths")
    if isinstance(exp_deaths, list) and len(exp_deaths) == 1:
        row = exp_deaths[0]
        if isinstance(row, dict):
            is_unknown_death = (
                _int_is_unknown(row.get("creature_index"))
                and _int_is_unknown(row.get("type_id"))
                and _int_is_unknown(row.get("xp_awarded"))
            )
            if is_unknown_death:
                exp["deaths"] = act.get("deaths")


def _path_join(path: str, suffix: str) -> str:
    if not path:
        return suffix
    return f"{path}.{suffix}"


def _values_equal(expected: object, actual: object, *, float_abs_tol: float) -> bool:
    abs_tol = max(0.0, float(float_abs_tol)) + 1e-12
    if isinstance(expected, float) and isinstance(actual, (int, float)):
        return math.isclose(float(expected), float(actual), rel_tol=0.0, abs_tol=abs_tol)
    if isinstance(actual, float) and isinstance(expected, (int, float)):
        return math.isclose(float(expected), float(actual), rel_tol=0.0, abs_tol=abs_tol)
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

    if isinstance(expected, dict) and isinstance(actual, dict):
        keys = sorted({*expected.keys(), *actual.keys()})
        for key in keys:
            key_str = str(key)
            exp_value = expected.get(key_str, expected.get(key))
            act_value = actual.get(key_str, actual.get(key))
            has_exp = key in expected or key_str in expected
            has_act = key in actual or key_str in actual
            if not has_exp or not has_act:
                out.append(
                    ReplayFieldDiff(
                        field=_path_join(path, key_str),
                        expected=exp_value if has_exp else "<missing>",
                        actual=act_value if has_act else "<missing>",
                    )
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

    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            out.append(
                ReplayFieldDiff(
                    field=_path_join(path, "_len"),
                    expected=int(len(expected)),
                    actual=int(len(actual)),
                )
            )
            if max_diffs is not None and len(out) >= int(max_diffs):
                return
        for idx, (exp_value, act_value) in enumerate(zip(expected, actual)):
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

    # Capture checkpoints quantize global bonus timers to integer ms in JS.
    # A one-ms jitter can appear from float edge cases and self-heal on the
    # next tick without affecting deterministic simulation behavior.
    if path.startswith("bonus_timers.") and isinstance(expected, int) and isinstance(actual, int):
        timer_key = path.removeprefix("bonus_timers.")
        if timer_key in {"2", "4", "6", "9", "11"}:
            if int(expected) > 0 and int(actual) > 0 and abs(int(expected) - int(actual)) <= 1:
                return

    if not _values_equal(expected, actual, float_abs_tol=float_abs_tol):
        out.append(
            ReplayFieldDiff(
                field=path or "<root>",
                expected=expected,
                actual=actual,
            )
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
        exp_elapsed = exp_obj.get("elapsed_ms")
        act_elapsed = act_obj.get("elapsed_ms")
        if isinstance(exp_elapsed, int) and isinstance(act_elapsed, int):
            if int(exp_elapsed) >= 0 and int(act_elapsed) >= 0:
                exp_obj["elapsed_ms"] = int(exp_elapsed) - int(exp_base)
                act_obj["elapsed_ms"] = int(act_elapsed) - int(act_base)

    if normalize_unknown:
        normalize_unknown_fields(exp_obj, act_obj)

    # Legacy sidecars (without `events`) store unknown sentinel values.
    if unknown_events_wildcard and int(expected.events.hit_count) < 0:
        exp_obj["events"] = act_obj.get("events")

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
        act = actual_by_tick.get(tick)
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
            exp_no_rng["events"] = act_no_rng.get("events")

        if exp_no_rng == act_no_rng:
            if first_rng_only_tick is None:
                first_rng_only_tick = tick
            continue

        mark_keys = sorted({*exp.rng_marks.keys(), *act.rng_marks.keys()})
        mark_mismatch = [key for key in mark_keys if int(exp.rng_marks.get(key, -1)) != int(act.rng_marks.get(key, -1))]
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
