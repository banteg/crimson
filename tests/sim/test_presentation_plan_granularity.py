from __future__ import annotations

from crimson.sim.clock import FixedStepClock
from crimson.sim.input_providers import FrameContext, InputStatus
from crimson.sim.tick_runner import TickBatchResult, TickRunner
from tests.support.builders.input_providers import StallableInputProvider
from tests.support.builders.session import make_session


def _advance_with_clock(
    *,
    runner: TickRunner,
    clock: FixedStepClock,
    start_tick: int,
    frame_index: int,
    dt_seconds: float,
    max_ticks: int | None = None,
) -> tuple[TickBatchResult, int, int]:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    if max_ticks is not None:
        ticks_requested = min(int(ticks_requested), max(0, int(max_ticks)))
    frame_index = int(frame_index) + 1
    runner.begin_frame(
        FrameContext(
            dt_seconds=float(dt_seconds),
            tick_dt_seconds=float(clock.dt_tick),
            frame_index=int(frame_index),
            candidate_ticks=max(0, int(ticks_requested)),
            is_replay=False,
        ),
    )
    batch = runner.advance_ticks(
        start_tick=int(start_tick),
        ticks_requested=max(0, int(ticks_requested)),
        tick_dt=float(clock.dt_tick),
    )
    if batch.batch_status in (InputStatus.STALLED, InputStatus.EOS):
        unconsumed_ticks = max(0, int(ticks_requested) - int(batch.ticks_completed))
        if unconsumed_ticks > 0:
            clock.accum += float(unconsumed_ticks) * float(clock.dt_tick)
    return batch, int(batch.next_tick_index), int(frame_index)


def test_tick_runner_returns_per_tick_plans_in_frame_order() -> None:
    session, _ = make_session()
    runner = TickRunner(
        session=session,
        input_provider=StallableInputProvider(),
    )

    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    result, next_tick_index, frame_index = _advance_with_clock(
        runner=runner,
        clock=clock,
        start_tick=next_tick_index,
        frame_index=frame_index,
        dt_seconds=2.0 / 60.0,
    )

    assert result.ticks_completed == 2
    assert result.batch_status is InputStatus.READY
    assert [row.source_tick.tick_index for row in result.completed_results] == [0, 1]


def test_tick_runner_returns_empty_plans_when_no_ticks_advanced() -> None:
    session, _ = make_session()
    runner = TickRunner(
        session=session,
        input_provider=StallableInputProvider(),
    )

    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    result, next_tick_index, frame_index = _advance_with_clock(
        runner=runner,
        clock=clock,
        start_tick=next_tick_index,
        frame_index=frame_index,
        dt_seconds=0.0,
    )

    assert result.ticks_completed == 0
    assert result.completed_results == []
