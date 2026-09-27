from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ...sim.clock import FixedStepClock
from ...sim.hooks import TickResult
from ...sim.presentation_step import DeterministicPresentationPlan

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


def advance_playback_frame(
    *,
    driver: PlaybackFrameDriver,
    runtime: WorldRuntime,
    clock: FixedStepClock,
    start_tick: int,
    dt_seconds: float,
    max_ticks: int | None,
    tick_limit: int,
    game_tune_started: bool,
) -> PlaybackFrameAdvance:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    if max_ticks is not None:
        ticks_requested = min(ticks_requested, max(0, int(max_ticks)))

    tick_results: list[TickResult] = []
    next_tick_index = int(start_tick)
    while len(tick_results) < ticks_requested and next_tick_index < int(tick_limit):
        tick_results.append(driver.step_tick(next_tick_index))
        next_tick_index += 1
    # Time the replay has no ticks for stays on the clock.
    clock.accum += float(ticks_requested - len(tick_results)) * float(clock.dt_tick)

    for tick_result in tick_results:
        runtime.advance_presentation_clock(
            dt_sim=float(tick_result.payload.dt_sim),
            game_tune_started=bool(game_tune_started),
        )
    return PlaybackFrameAdvance(
        plans=tuple(tick_result.payload.presentation for tick_result in tick_results),
        tick_results=tuple(tick_results),
        next_tick_index=next_tick_index,
        ticks_requested=ticks_requested,
    )
