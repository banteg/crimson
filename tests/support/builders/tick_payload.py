from __future__ import annotations

from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.sessions import DeterministicSessionTick
from crimson.sim.step_pipeline import PresentationRngTrace
from crimson.sim.terrain_fx import TerrainFxBatch
from crimson.sim.timing import FrameTiming
from crimson.sim.world_state import WorldEvents
from grim.sfx_map import SfxId


def make_tick_payload(
    *,
    dt_sim: float = 1.0 / 60.0,
    elapsed_ms: float = 16.67,
    creature_count: int = 0,
    terrain_fx: TerrainFxBatch = TerrainFxBatch(),
    post_apply_sfx: tuple[SfxId, ...] = (),
) -> DeterministicSessionTick:
    timing = FrameTiming(
        dt=dt_sim,
        time_scale_active_entry=False,
        time_scale_factor=1.0,
        zero_gate_active=False,
        dt_sim=dt_sim,
    )
    return DeterministicSessionTick(
        elapsed_ms=elapsed_ms,
        creature_count_world_step=creature_count,
        dt_sim=dt_sim,
        timing=timing,
        events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
        presentation=DeterministicPresentationPlan(
            terrain_fx=terrain_fx,
            post_apply_sfx=tuple(post_apply_sfx),
        ),
        presentation_rng_trace=PresentationRngTrace(),
    )
