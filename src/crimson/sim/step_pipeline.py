from __future__ import annotations

import msgspec

from ..math_parity import f32
from .presentation_step import DeterministicPresentationPlan
from .timing import FrameTiming
from .world_state import WorldEvents


class PresentationRngTrace(msgspec.Struct):
    draws_total: int = 0


class DeterministicStepResult(msgspec.Struct):
    dt_sim: float
    timing: FrameTiming
    events: WorldEvents
    presentation: DeterministicPresentationPlan
    presentation_rng_trace: PresentationRngTrace


def time_scale_reflex_boost_bonus(
    *,
    reflex_boost_timer: float,
    time_scale_active: bool,
    dt: float,
) -> float:
    """Apply Reflex Boost time scaling, matching the classic frame loop latch semantics."""

    # Native stores frame delta time in float32 (`frame_dt`). Many downstream systems
    # multiply `frame_dt` before rounding back to float32, so the *input* precision
    # matters even when Reflex Boost is inactive.
    dt_f32 = f32(float(dt))
    if not (float(dt_f32) > 0.0):
        return float(dt_f32)
    if not time_scale_active:
        return float(dt_f32)

    time_scale_factor = time_scale_reflex_boost_factor(
        reflex_boost_timer=float(reflex_boost_timer),
        time_scale_active=bool(time_scale_active),
    )
    return float(f32(float(dt_f32) * float(time_scale_factor)))


def time_scale_reflex_boost_factor(
    *,
    reflex_boost_timer: float,
    time_scale_active: bool,
) -> float:
    if not bool(time_scale_active):
        return 1.0
    reflex_f32 = f32(float(reflex_boost_timer))
    time_scale_factor = f32(0.3)
    if float(reflex_f32) < 1.0:
        time_scale_factor = f32((1.0 - float(reflex_f32)) * 0.7 + 0.3)
    return float(time_scale_factor)
