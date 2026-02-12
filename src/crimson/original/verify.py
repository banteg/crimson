from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..game_modes import GameMode
from ..sim.runners import RunResult, run_rush_replay, run_survival_replay
from ..replay.checkpoints import ReplayCheckpoint
from .capture import (
    CaptureFile,
    build_capture_dt_frame_overrides,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    convert_capture_to_checkpoints,
    convert_capture_to_replay,
)
from .diff import ReplayFieldDiff, checkpoint_field_diffs


class CaptureVerifyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CaptureVerifyFailure:
    kind: str
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None = None
    field_diffs: tuple[ReplayFieldDiff, ...] = ()


@dataclass(frozen=True, slots=True)
class CaptureVerifyResult:
    ok: bool
    checked_count: int
    expected_count: int
    actual_count: int
    elapsed_baseline_tick: int | None = None
    elapsed_offset_ms: int | None = None
    failure: CaptureVerifyFailure | None = None


def _allow_capture_sample_creature_count(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
    capture_sample_creature_counts: dict[int, int],
    capture_active_corpse_below_despawn_ticks: set[int] | None = None,
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "creature_count" for diff in field_diffs):
        return False
    if not capture_sample_creature_counts:
        return False

    sample_count = capture_sample_creature_counts.get(int(tick))
    if sample_count is None or int(sample_count) < 0:
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    if expected_tick is None or actual_tick is None:
        return False

    expected_count = int(expected_tick.creature_count)
    actual_count = int(actual_tick.creature_count)
    if expected_count < 0 or actual_count < 0:
        return False

    # `checkpoint.creature_count` can lag the sampled creature pool in captures.
    # When replay count matches sampled active entries exactly, ignore this field.
    if actual_count == int(sample_count) and expected_count != int(sample_count):
        return True

    # Some captures sample creature slots before render-time corpse culling.
    # In those ticks, sampled active count can exceed replay by exactly one when a
    # corpse is already below the native despawn threshold (< -10.0 hitbox_size).
    if (
        expected_count == int(sample_count)
        and actual_count == int(sample_count) - 1
        and capture_active_corpse_below_despawn_ticks is not None
        and int(tick) in capture_active_corpse_below_despawn_ticks
    ):
        return True

    return False


def _capture_sample_creature_counts(capture: CaptureFile) -> dict[int, int]:
    out: dict[int, int] = {}
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        if tick_index < 0:
            continue
        samples = tick.samples
        if samples is None:
            continue
        creatures = samples.creatures
        if not isinstance(creatures, list):
            continue
        out[int(tick_index)] = int(len(creatures))
    return out


def _capture_active_corpse_below_despawn_ticks(capture: CaptureFile) -> set[int]:
    out: set[int] = set()
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        if tick_index < 0:
            continue
        samples = tick.samples
        if samples is None:
            continue
        creatures = samples.creatures
        if not isinstance(creatures, list):
            continue
        for creature in creatures:
            if int(creature.active) == 0:
                continue
            if float(creature.hp) > 0.0:
                continue
            if float(creature.hitbox_size) < -10.0:
                out.add(int(tick_index))
                break
    return out


def verify_capture(
    capture: CaptureFile,
    *,
    seed: int | None = None,
    max_ticks: int | None = None,
    strict_events: bool = False,
    trace_rng: bool = False,
    max_field_diffs: int = 16,
    float_abs_tol: float = 0.001,
    aim_scheme_overrides_by_player: Mapping[int, int] | None = None,
) -> tuple[CaptureVerifyResult, RunResult]:
    expected = convert_capture_to_checkpoints(capture).checkpoints
    if max_ticks is not None:
        tick_cap = max(0, int(max_ticks))
        expected = [ckpt for ckpt in expected if int(ckpt.tick_index) < int(tick_cap)]

    replay = convert_capture_to_replay(
        capture,
        seed=seed,
        aim_scheme_overrides_by_player=aim_scheme_overrides_by_player,
    )
    dt_frame_overrides = build_capture_dt_frame_overrides(
        capture,
        tick_rate=int(replay.header.tick_rate),
    )
    dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(capture)
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected}
    actual: list[ReplayCheckpoint] = []

    mode = int(replay.header.game_mode_id)
    inter_tick_rand_draws = 1
    inter_tick_rand_draws_by_tick = build_capture_inter_tick_rand_draws_overrides(capture)
    if mode == int(GameMode.SURVIVAL):
        run_result = run_survival_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=False,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        )
    elif mode == int(GameMode.RUSH):
        run_result = run_rush_replay(
            replay,
            max_ticks=max_ticks,
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=False,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        )
    else:
        raise CaptureVerifyError(f"unsupported game mode for capture verification: {mode}")

    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
    sample_creature_counts = _capture_sample_creature_counts(capture)
    sample_corpse_below_despawn_ticks = _capture_active_corpse_below_despawn_ticks(capture)
    checked_count = 0
    elapsed_baseline: tuple[int, int] | None = None
    elapsed_baseline_tick: int | None = None
    elapsed_offset_ms: int | None = None

    for exp in expected:
        checked_count += 1
        tick = int(exp.tick_index)
        act = actual_by_tick.get(tick)
        if act is None:
            return (
                CaptureVerifyResult(
                    ok=False,
                    checked_count=checked_count,
                    expected_count=len(expected),
                    actual_count=len(actual),
                    elapsed_baseline_tick=elapsed_baseline_tick,
                    elapsed_offset_ms=elapsed_offset_ms,
                    failure=CaptureVerifyFailure(
                        kind="missing_checkpoint",
                        tick_index=tick,
                        expected=exp,
                        actual=None,
                    ),
                ),
                run_result,
            )

        if elapsed_baseline is None and int(exp.elapsed_ms) >= 0 and int(act.elapsed_ms) >= 0:
            elapsed_baseline = (int(exp.elapsed_ms), int(act.elapsed_ms))
            elapsed_baseline_tick = int(tick)
            elapsed_offset_ms = int(act.elapsed_ms) - int(exp.elapsed_ms)

        exp_for_diff = replace(exp, elapsed_ms=-1)
        field_diffs = checkpoint_field_diffs(
            exp_for_diff,
            act,
            include_hash_fields=False,
            include_rng_fields=False,
            normalize_unknown=True,
            unknown_events_wildcard=True,
            elapsed_baseline=elapsed_baseline,
            max_diffs=max_field_diffs,
            float_abs_tol=float(float_abs_tol),
        )
        if _allow_capture_sample_creature_count(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
            capture_sample_creature_counts=sample_creature_counts,
            capture_active_corpse_below_despawn_ticks=sample_corpse_below_despawn_ticks,
        ):
            continue
        if field_diffs:
            return (
                CaptureVerifyResult(
                    ok=False,
                    checked_count=checked_count,
                    expected_count=len(expected),
                    actual_count=len(actual),
                    elapsed_baseline_tick=elapsed_baseline_tick,
                    elapsed_offset_ms=elapsed_offset_ms,
                    failure=CaptureVerifyFailure(
                        kind="state_mismatch",
                        tick_index=tick,
                        expected=exp,
                        actual=act,
                        field_diffs=tuple(field_diffs),
                    ),
                ),
                run_result,
            )

    return (
        CaptureVerifyResult(
            ok=True,
            checked_count=checked_count,
            expected_count=len(expected),
            actual_count=len(actual),
            elapsed_baseline_tick=elapsed_baseline_tick,
            elapsed_offset_ms=elapsed_offset_ms,
            failure=None,
        ),
        run_result,
    )
