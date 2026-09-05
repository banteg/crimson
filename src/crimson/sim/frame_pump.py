from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .hooks import TickResult

from .clock import FixedStepClock
from .input_providers import FrameContext, InputStatus
from .tick_runner import TickBatchResult


class TickFrameRunner(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def advance_ticks(
        self,
        *,
        start_tick: int,
        ticks_requested: int,
        tick_dt: float,
        after_tick: Callable[[TickResult], bool | None] | None = None,
    ) -> TickBatchResult: ...


@dataclass(frozen=True, slots=True)
class TickFrameAdvance:
    batch: TickBatchResult
    frame_index: int
    next_tick_index: int
    ticks_requested: int


def advance_tick_runner_frame(
    *,
    runner: TickFrameRunner,
    start_tick: int,
    frame_index: int,
    ticks_requested: int,
    dt_seconds: float,
    tick_dt_seconds: float,
    is_replay: bool,
    refund_clock: FixedStepClock | None = None,
    after_tick: Callable[[TickResult], bool | None] | None = None,
) -> TickFrameAdvance:
    next_frame_index = int(frame_index) + 1
    ticks_requested = max(0, int(ticks_requested))

    runner.begin_frame(
        FrameContext(
            dt_seconds=float(dt_seconds),
            tick_dt_seconds=float(tick_dt_seconds),
            frame_index=int(next_frame_index),
            candidate_ticks=int(ticks_requested),
            is_replay=bool(is_replay),
        ),
    )
    if after_tick is None:
        batch = runner.advance_ticks(
            start_tick=int(start_tick),
            ticks_requested=int(ticks_requested),
            tick_dt=float(tick_dt_seconds),
        )
    else:
        batch = runner.advance_ticks(
            start_tick=int(start_tick),
            ticks_requested=int(ticks_requested),
            tick_dt=float(tick_dt_seconds),
            after_tick=after_tick,
        )
    next_tick_index = int(batch.next_tick_index)

    if refund_clock is not None and batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
        unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
        if unconsumed_ticks > 0:
            refund_clock.accum += float(unconsumed_ticks) * float(tick_dt_seconds)

    return TickFrameAdvance(
        batch=batch,
        frame_index=int(next_frame_index),
        next_tick_index=int(next_tick_index),
        ticks_requested=int(ticks_requested),
    )
