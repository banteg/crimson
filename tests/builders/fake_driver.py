from __future__ import annotations

from dataclasses import dataclass

from builders.tick_payload import make_tick_payload

from crimson.sim.driver.playback_driver import PlaybackTickOutcome
from crimson.sim.world_state import WorldEvents, WorldState


@dataclass
class FakePlaybackDriver:
    """Minimal fake driver for replay playback mode tests.

    Returns stub ``PlaybackTickOutcome`` objects from ``step_tick``.
    """

    tick_limit: int = 0
    on_step: object | None = None

    def step_tick(self, tick_index: int) -> PlaybackTickOutcome:
        if self.on_step is not None:
            self.on_step()
        payload = make_tick_payload()
        return PlaybackTickOutcome(
            tick_index=int(tick_index),
            dt_tick=1.0 / 60.0,
            dt_tick_ms_i32=16,
            commands=[],
            world=WorldState.build(
                world_size=1024.0,
                demo_mode_active=False,
                hardcore=False,
                difficulty_level=0,
            ),
            step=payload.step,
            step_events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
            elapsed_ms=float(payload.elapsed_ms),
            dt_sim=float(payload.step.dt_sim),
            rng_marks={},
            creature_count_world_step=0,
            tick_rng_rows=[],
        )
