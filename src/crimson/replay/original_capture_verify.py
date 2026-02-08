from __future__ import annotations

from dataclasses import dataclass, replace

from ..game_modes import GameMode
from ..sim.runners import RunResult, run_rush_replay, run_survival_replay
from .checkpoints import ReplayCheckpoint
from .diff import ReplayFieldDiff, checkpoint_field_diffs
from .original_capture import (
    OriginalCaptureSidecar,
    build_original_capture_dt_frame_overrides,
    convert_original_capture_to_checkpoints,
    convert_original_capture_to_replay,
)


class OriginalCaptureVerifyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OriginalCaptureVerifyFailure:
    kind: str
    tick_index: int
    expected: ReplayCheckpoint
    actual: ReplayCheckpoint | None = None
    field_diffs: tuple[ReplayFieldDiff, ...] = ()


@dataclass(frozen=True, slots=True)
class OriginalCaptureVerifyResult:
    ok: bool
    checked_count: int
    expected_count: int
    actual_count: int
    elapsed_baseline_tick: int | None = None
    elapsed_offset_ms: int | None = None
    failure: OriginalCaptureVerifyFailure | None = None


def _allow_one_tick_creature_count_lag(
    *,
    tick: int,
    field_diffs: list[ReplayFieldDiff],
    expected_by_tick: dict[int, ReplayCheckpoint],
    actual_by_tick: dict[int, ReplayCheckpoint],
) -> bool:
    if not field_diffs:
        return False
    if any(str(diff.field) != "creature_count" for diff in field_diffs):
        return False

    expected_tick = expected_by_tick.get(int(tick))
    actual_tick = actual_by_tick.get(int(tick))
    if expected_tick is None or actual_tick is None:
        return False

    expected_count = int(expected_tick.creature_count)
    actual_count = int(actual_tick.creature_count)
    if expected_count < 0 or actual_count < 0:
        return False
    if abs(expected_count - actual_count) != 1:
        return False

    prev_expected = expected_by_tick.get(int(tick) - 1)
    prev_actual = actual_by_tick.get(int(tick) - 1)
    if (
        prev_expected is not None
        and prev_actual is not None
        and int(prev_expected.creature_count) == actual_count
        and int(prev_actual.creature_count) == int(prev_expected.creature_count)
    ):
        return True

    next_expected = expected_by_tick.get(int(tick) + 1)
    next_actual = actual_by_tick.get(int(tick) + 1)
    if (
        next_expected is not None
        and next_actual is not None
        and int(next_expected.creature_count) == actual_count
        and int(next_actual.creature_count) == int(next_expected.creature_count)
    ):
        return True

    return False


def verify_original_capture(
    capture: OriginalCaptureSidecar,
    *,
    seed: int | None = None,
    max_ticks: int | None = None,
    strict_events: bool = False,
    trace_rng: bool = False,
    max_field_diffs: int = 16,
    float_abs_tol: float = 0.001,
) -> tuple[OriginalCaptureVerifyResult, RunResult]:
    expected = convert_original_capture_to_checkpoints(capture).checkpoints
    if max_ticks is not None:
        tick_cap = max(0, int(max_ticks))
        expected = [ckpt for ckpt in expected if int(ckpt.tick_index) < int(tick_cap)]

    replay = convert_original_capture_to_replay(capture, seed=seed)
    dt_frame_overrides = build_original_capture_dt_frame_overrides(
        capture,
        tick_rate=int(replay.header.tick_rate),
    )
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected}
    actual: list[ReplayCheckpoint] = []

    mode = int(replay.header.game_mode_id)
    # Ghidra decompile (`console_hotkey_update`) shows one unconditional
    # `crt_rand()` draw outside `gameplay_update_and_render` each frame.
    inter_tick_rand_draws = 1
    if mode == int(GameMode.SURVIVAL):
        run_result = run_survival_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
        )
    elif mode == int(GameMode.RUSH):
        run_result = run_rush_replay(
            replay,
            max_ticks=max_ticks,
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=True,
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
            dt_frame_overrides=dt_frame_overrides,
            inter_tick_rand_draws=int(inter_tick_rand_draws),
        )
    else:
        raise OriginalCaptureVerifyError(f"unsupported game mode for original capture verification: {mode}")

    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected}
    actual_by_tick = {int(ckpt.tick_index): ckpt for ckpt in actual}
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
                OriginalCaptureVerifyResult(
                    ok=False,
                    checked_count=checked_count,
                    expected_count=len(expected),
                    actual_count=len(actual),
                    elapsed_baseline_tick=elapsed_baseline_tick,
                    elapsed_offset_ms=elapsed_offset_ms,
                    failure=OriginalCaptureVerifyFailure(
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

        # Raw original captures carry wall-clock deltas from variable frame pacing.
        # Current replay reconstruction drives a fixed simulation step, so elapsed
        # values are not yet authoritative for divergence detection.
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
        if _allow_one_tick_creature_count_lag(
            tick=int(tick),
            field_diffs=field_diffs,
            expected_by_tick=expected_by_tick,
            actual_by_tick=actual_by_tick,
        ):
            continue
        if field_diffs:
            return (
                OriginalCaptureVerifyResult(
                    ok=False,
                    checked_count=checked_count,
                    expected_count=len(expected),
                    actual_count=len(actual),
                    elapsed_baseline_tick=elapsed_baseline_tick,
                    elapsed_offset_ms=elapsed_offset_ms,
                    failure=OriginalCaptureVerifyFailure(
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
        OriginalCaptureVerifyResult(
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
