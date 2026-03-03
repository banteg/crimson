from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Literal, TypeAlias

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .strict_compare import strict_mismatch_payload

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

class _MissingCheckpointFailure(msgspec.Struct, frozen=True):
    tick_index: int
    expected: ReplayCheckpoint
    kind: Literal["missing_checkpoint"] = "missing_checkpoint"
    actual: None = None
    first_rng_mark: None = None


class _CommandMismatchFailure(msgspec.Struct, frozen=True):
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint
    kind: Literal["command_mismatch"] = "command_mismatch"
    first_rng_mark: None = None


class _StateMismatchFailure(msgspec.Struct, frozen=True):
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint
    kind: Literal["state_mismatch"] = "state_mismatch"
    first_rng_mark: str | None = None


ReplayDiffFailure: TypeAlias = (
    _MissingCheckpointFailure
    | _CommandMismatchFailure
    | _StateMismatchFailure
)


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


def checkpoint_deepdiff(
    expected: ReplayCheckpoint,
    actual: ReplayCheckpoint,
) -> CheckpointDeepDiff | None:
    mismatches, diff_count, _pretty = strict_mismatch_payload(expected, actual)
    if int(diff_count) <= 0:
        return None

    payload: dict[str, object] = {"mismatches": mismatches}
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
                failure=_MissingCheckpointFailure(
                    tick_index=tick,
                    expected=exp,
                ),
            )

        if str(exp.command_hash) and str(exp.command_hash) != str(act.command_hash):
            return ReplayDiffResult(
                ok=False,
                checked_count=checked_count,
                first_rng_only_tick=first_rng_only_tick,
                failure=_CommandMismatchFailure(
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
            failure=_StateMismatchFailure(
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
