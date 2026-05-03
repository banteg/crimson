from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from math import isclose

from crimson.sim.clock import FixedStepClock
from crimson.sim.frame_pump import advance_tick_runner_frame
from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import FrameContext, InputStatus
from crimson.sim.tick_runner import TickBatchResult


@dataclass
class _RecordingRunner:
    batch: TickBatchResult
    frame_ctx: FrameContext | None = None
    start_tick: int | None = None
    ticks_requested: int | None = None
    tick_dt: float | None = None
    after_tick: Callable[[TickResult], None] | None = None

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        self.frame_ctx = frame_ctx

    def advance_ticks(
        self,
        *,
        start_tick: int,
        ticks_requested: int,
        tick_dt: float,
        after_tick: Callable[[TickResult], None] | None = None,
    ) -> TickBatchResult:
        self.start_tick = int(start_tick)
        self.ticks_requested = int(ticks_requested)
        self.tick_dt = float(tick_dt)
        self.after_tick = after_tick
        return self.batch


def test_advance_tick_runner_frame_builds_context_and_tracks_indices() -> None:
    runner = _RecordingRunner(
        batch=TickBatchResult(
            ticks_completed=2,
            batch_status=InputStatus.READY,
            next_tick_index=12,
        ),
    )

    advance = advance_tick_runner_frame(
        runner=runner,
        start_tick=10,
        frame_index=4,
        ticks_requested=3,
        dt_seconds=0.25,
        tick_dt_seconds=1.0 / 60.0,
        is_networked=True,
        is_replay=False,
    )

    assert runner.frame_ctx is not None
    assert runner.frame_ctx.frame_index == 5
    assert runner.frame_ctx.candidate_ticks == 3
    assert runner.frame_ctx.is_networked is True
    assert runner.frame_ctx.is_replay is False
    assert isclose(float(runner.frame_ctx.dt_seconds), 0.25)
    assert isclose(float(runner.frame_ctx.tick_dt_seconds), 1.0 / 60.0)
    assert runner.start_tick == 10
    assert runner.ticks_requested == 3
    assert runner.tick_dt is not None
    assert isclose(float(runner.tick_dt), 1.0 / 60.0)
    assert advance.batch is runner.batch
    assert advance.frame_index == 5
    assert advance.next_tick_index == 12
    assert advance.ticks_requested == 3


def test_advance_tick_runner_frame_refunds_stalled_ticks_to_clock() -> None:
    clock = FixedStepClock(tick_rate=60)
    runner = _RecordingRunner(
        batch=TickBatchResult(
            ticks_completed=1,
            batch_status=InputStatus.STALLED,
            next_tick_index=7,
        ),
    )

    advance_tick_runner_frame(
        runner=runner,
        start_tick=6,
        frame_index=1,
        ticks_requested=3,
        dt_seconds=3.0 / 60.0,
        tick_dt_seconds=float(clock.dt_tick),
        is_networked=False,
        is_replay=False,
        refund_clock=clock,
    )

    assert isclose(float(clock.accum), 2.0 * float(clock.dt_tick))


def test_advance_tick_runner_frame_refunds_eos_ticks_to_clock() -> None:
    clock = FixedStepClock(tick_rate=60)
    runner = _RecordingRunner(
        batch=TickBatchResult(
            ticks_completed=0,
            batch_status=InputStatus.EOS,
            next_tick_index=9,
        ),
    )

    advance_tick_runner_frame(
        runner=runner,
        start_tick=9,
        frame_index=2,
        ticks_requested=2,
        dt_seconds=2.0 / 60.0,
        tick_dt_seconds=float(clock.dt_tick),
        is_networked=False,
        is_replay=False,
        refund_clock=clock,
    )

    assert isclose(float(clock.accum), 2.0 * float(clock.dt_tick))


def test_advance_tick_runner_frame_does_not_refund_when_all_ticks_consumed() -> None:
    clock = FixedStepClock(tick_rate=60)
    runner = _RecordingRunner(
        batch=TickBatchResult(
            ticks_completed=2,
            batch_status=InputStatus.STALLED,
            next_tick_index=5,
        ),
    )

    advance_tick_runner_frame(
        runner=runner,
        start_tick=3,
        frame_index=0,
        ticks_requested=2,
        dt_seconds=2.0 / 60.0,
        tick_dt_seconds=float(clock.dt_tick),
        is_networked=False,
        is_replay=False,
        refund_clock=clock,
    )

    assert isclose(float(clock.accum), 0.0)


def test_advance_tick_runner_frame_does_not_refund_without_clock() -> None:
    runner = _RecordingRunner(
        batch=TickBatchResult(
            ticks_completed=0,
            batch_status=InputStatus.STALLED,
            next_tick_index=4,
        ),
    )

    advance = advance_tick_runner_frame(
        runner=runner,
        start_tick=4,
        frame_index=3,
        ticks_requested=2,
        dt_seconds=2.0 / 60.0,
        tick_dt_seconds=1.0 / 60.0,
        is_networked=False,
        is_replay=False,
        refund_clock=None,
    )

    assert advance.frame_index == 4
    assert advance.next_tick_index == 4
