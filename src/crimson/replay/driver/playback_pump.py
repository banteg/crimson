from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ...sim.batch_apply import PresentationTickOutput, SimMetadataSink, apply_tick_to_sim
from ...sim.clock import FixedStepClock
from ...sim.frame_pump import advance_tick_runner_frame
from ...sim.hooks import TickResult
from ...sim.input_providers import FrameContext, InputStatus
from ...sim.tick_runner import TickBatchResult


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


class _PlaybackStepRunner:
    def __init__(self, *, driver: PlaybackFrameDriver, tick_limit: int) -> None:
        self._driver = driver
        self._tick_limit = int(tick_limit)

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def advance_ticks(
        self,
        *,
        start_tick: int,
        ticks_requested: int,
        tick_dt: float,
        after_tick: Callable[[TickResult], None] | None = None,
    ) -> TickBatchResult:
        _ = tick_dt
        completed_results: list[TickResult] = []
        next_tick_index = int(start_tick)
        batch_status = InputStatus.READY
        while len(completed_results) < max(0, int(ticks_requested)):
            if next_tick_index >= int(self._tick_limit):
                batch_status = InputStatus.EOS
                break
            tick_result = self._driver.step_tick(next_tick_index)
            completed_results.append(tick_result)
            if after_tick is not None:
                after_tick(tick_result)
            next_tick_index += 1

        return TickBatchResult(
            ticks_completed=len(completed_results),
            batch_status=batch_status,
            next_tick_index=int(next_tick_index),
            completed_results=completed_results,
        )


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

    advance = advance_tick_runner_frame(
        runner=_PlaybackStepRunner(driver=driver, tick_limit=int(tick_limit)),
        start_tick=int(start_tick),
        frame_index=int(frame_index),
        ticks_requested=int(ticks_requested),
        dt_seconds=float(dt_seconds),
        tick_dt_seconds=float(clock.dt_tick),
        is_networked=False,
        is_replay=True,
        refund_clock=clock,
    )
    tick_results = list(advance.batch.completed_results)
    outputs: list[PresentationTickOutput] = []
    for tick_result in tick_results:
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

    return PlaybackFrameAdvance(
        outputs=tuple(outputs),
        tick_results=tuple(tick_results),
        frame_index=int(advance.frame_index),
        next_tick_index=int(advance.next_tick_index),
        ticks_requested=int(advance.ticks_requested),
        ticks_completed=int(advance.batch.ticks_completed),
    )
