from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..batch_apply import PresentationTickOutput, SimMetadataSink, apply_tick_to_sim
from ..clock import FixedStepClock
from ..hooks import TickResult


class PlaybackFrameDriver(Protocol):
    def step_tick(self, tick_index: int) -> TickResult: ...


@dataclass(frozen=True, slots=True)
class PlaybackFrameAdvance:
    outputs: tuple[PresentationTickOutput, ...]
    tick_results: tuple[TickResult, ...]
    frame_index: int
    next_tick_index: int
    ticks_requested: int
    ticks_completed: int


def advance_playback_frame(
    *,
    driver: PlaybackFrameDriver,
    sim_world: SimMetadataSink,
    clock: FixedStepClock,
    start_tick: int,
    frame_index: int,
    dt_seconds: float,
    max_ticks: int | None,
    tick_limit: int,
    game_tune_started: bool,
) -> PlaybackFrameAdvance:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    if max_ticks is not None:
        ticks_requested = min(int(ticks_requested), max(0, int(max_ticks)))

    next_frame_index = int(frame_index) + 1
    next_tick_index = int(start_tick)

    outputs: list[PresentationTickOutput] = []
    tick_results: list[TickResult] = []

    while len(tick_results) < ticks_requested and next_tick_index < int(tick_limit):
        tick_result = driver.step_tick(int(next_tick_index))
        apply_tick_to_sim(
            sim_world=sim_world,
            step=tick_result.payload.step,
            game_tune_started=bool(game_tune_started),
        )
        outputs.append(PresentationTickOutput(
            tick_index=int(tick_result.source_tick.tick_index),
            dt_sim=float(tick_result.payload.step.dt_sim),
            presentation=tick_result.payload.step.presentation,
        ))
        tick_results.append(tick_result)
        next_tick_index += 1

    ticks_completed = len(tick_results)
    if ticks_completed < ticks_requested and next_tick_index >= int(tick_limit):
        clock.accum += float(ticks_requested - ticks_completed) * float(clock.dt_tick)

    return PlaybackFrameAdvance(
        outputs=tuple(outputs),
        tick_results=tuple(tick_results),
        frame_index=int(next_frame_index),
        next_tick_index=int(next_tick_index),
        ticks_requested=int(ticks_requested),
        ticks_completed=int(ticks_completed),
    )
