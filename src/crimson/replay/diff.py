from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass

from .checkpoints import ReplayCheckpoint

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


def _without_hash_and_rng(checkpoint: ReplayCheckpoint) -> dict[str, object]:
    obj = asdict(checkpoint)
    for key in ("state_hash", "rng_state", "rng_marks", "command_hash"):
        obj.pop(key, None)
    return obj


def _int_is_unknown(value: object) -> bool:
    return isinstance(value, int) and int(value) < 0


def _normalize_unknown_fields(exp: dict[str, object], act: dict[str, object]) -> None:
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

        exp_no_rng = _without_hash_and_rng(exp)
        act_no_rng = _without_hash_and_rng(act)
        _normalize_unknown_fields(exp_no_rng, act_no_rng)
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
