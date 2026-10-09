from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ...sim.clock import FixedStepClock
from ...sim.hooks import TickResult
from ...sim.presentation_step import DeterministicPresentationPlan
from .setup import ReplayRunnerError

if TYPE_CHECKING:
    from ...world.runtime import WorldRuntime


class PlaybackFrameDriver(Protocol):
    def step_tick(self, tick_index: int) -> TickResult: ...


@dataclass(frozen=True, slots=True)
class PlaybackFrameAdvance:
    plans: tuple[DeterministicPresentationPlan, ...]
    tick_results: tuple[TickResult, ...]
    next_tick_index: int
    ticks_requested: int
    # The tick the simulation refused (a command or input the run could not have issued); playback stops before it.
    refused_tick: int | None = None


def advance_playback_frame(
    *,
    driver: PlaybackFrameDriver,
    runtime: WorldRuntime,
    clock: FixedStepClock,
    start_tick: int,
    dt_seconds: float,
    max_ticks: int | None,
    tick_limit: int,
) -> PlaybackFrameAdvance:
    # Replay time, not a frame's: the viewer caps the frame dt before scaling it by the playback speed,
    # and a skip asks for all of its seconds at once.
    ticks_requested = int(clock.advance(float(dt_seconds), max_dt=math.inf))
    if max_ticks is not None:
        ticks_requested = min(ticks_requested, max(0, int(max_ticks)))

    tick_results: list[TickResult] = []
    next_tick_index = int(start_tick)
    refused_tick: int | None = None
    try:
        while len(tick_results) < ticks_requested and next_tick_index < int(tick_limit):
            tick_results.append(driver.step_tick(next_tick_index))
            next_tick_index += 1
    except ReplayRunnerError:
        refused_tick = next_tick_index
    # Time the replay has no ticks for stays on the clock.
    clock.accum += float(ticks_requested - len(tick_results)) * float(clock.dt_tick)

    for tick_result in tick_results:
        runtime.presentation.advance(float(tick_result.payload.dt_sim))
    return PlaybackFrameAdvance(
        plans=tuple(tick_result.payload.presentation for tick_result in tick_results),
        tick_results=tuple(tick_results),
        next_tick_index=next_tick_index,
        ticks_requested=ticks_requested,
        refused_tick=refused_tick,
    )
