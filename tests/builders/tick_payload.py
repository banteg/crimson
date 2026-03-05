from __future__ import annotations

from crimson.sim.presentation_step import PresentationStepCommands
from crimson.sim.sessions import DeterministicSessionTick
from crimson.sim.step_pipeline import DeterministicStepResult, PresentationRngTrace
from crimson.sim.timing import FrameTiming
from crimson.sim.world_state import WorldEvents


def make_tick_payload(
    *,
    dt_sim: float = 1.0 / 60.0,
    elapsed_ms: float = 16.67,
    creature_count: int = 0,
    presentation_plan_ms: float = 0.0,
    post_apply_sfx_keys: tuple[str, ...] = (),
) -> DeterministicSessionTick:
    timing = FrameTiming(
        dt=dt_sim,
        time_scale_active_entry=False,
        time_scale_factor=1.0,
        zero_gate_active=False,
        dt_sim=dt_sim,
    )
    step = DeterministicStepResult(
        dt_sim=dt_sim,
        timing=timing,
        events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
        presentation=PresentationStepCommands(),
        presentation_plan_ms=float(presentation_plan_ms),
        presentation_rng_trace=PresentationRngTrace(),
        post_apply_sfx_keys=tuple(str(key) for key in post_apply_sfx_keys),
    )
    return DeterministicSessionTick(
        step=step,
        elapsed_ms=elapsed_ms,
        rng_marks={},
        creature_count_world_step=creature_count,
    )
