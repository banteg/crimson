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


def test_tick_runner_exposes_tick_inputs_for_explicit_replay_recording() -> None:
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
        dt_seconds=1.0 / 60.0,
    )

    assert result.ticks_completed == 1
    assert len(result.completed_results) == 1
    assert result.completed_results[0].source_tick.inputs is not None
    assert len(result.completed_results[0].source_tick.inputs or []) == 1


def test_tick_runner_advances_all_candidate_ticks_without_hook_stop_callbacks() -> None:
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
    assert [row.source_tick.tick_index for row in result.completed_results] == [0, 1]


def test_tick_runner_after_tick_callback_observes_each_tick_before_batch_end() -> None:
    session, _ = make_session()
    runner = TickRunner(
        session=session,
        input_provider=StallableInputProvider(),
    )

    elapsed_by_tick: list[tuple[int, int]] = []
    runner.begin_frame(
        FrameContext(
            dt_seconds=2.0 / 60.0,
            tick_dt_seconds=1.0 / 60.0,
            frame_index=1,
            candidate_ticks=2,
        ),
    )
    batch = runner.advance_ticks(
        start_tick=0,
        ticks_requested=2,
        tick_dt=1.0 / 60.0,
        after_tick=lambda tick: elapsed_by_tick.append(
            (int(tick.source_tick.tick_index), int(tick.payload.elapsed_ms)),
        ),
    )

    assert batch.ticks_completed == 2
    assert elapsed_by_tick == [(0, 16), (1, 32)]
