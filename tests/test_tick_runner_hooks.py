from __future__ import annotations

import msgspec
import pytest

from crimson.sim.clock import FixedStepClock
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, GameCommand, InputProvider, InputStatus, TickInput
from crimson.sim.tick_runner import TickBatchResult, TickRunner
from crimson.sim.timing import FrameTiming


class _FakeTick(msgspec.Struct):
    dt_sim: float = 1.0 / 60.0
    presentation_plan_ms: float = 0.0


def _timing(dt: float) -> FrameTiming:
    return FrameTiming(dt=dt, time_scale_active_entry=False, time_scale_factor=1.0, zero_gate_active=False, dt_sim=dt)


class _FakeSession:
    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False, commands: tuple = ()) -> _FakeTick:
        _ = timing, inputs, trace_rng, commands
        return _FakeTick()


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
            is_networked=False,
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


class _FixedInputProvider(InputProvider):
    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> TickInput:
        _ = tick_index
        return TickInput(status=InputStatus.READY, inputs=[PlayerInput()])

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        _ = tick_index
        return []

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command: GameCommand) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        _ = tick_index
        return default_dt


def test_tick_runner_exposes_tick_inputs_for_explicit_replay_recording() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
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
    assert result.completed_results[0].inputs is not None
    assert len(result.completed_results[0].inputs or []) == 1


def test_tick_runner_advances_all_candidate_ticks_without_hook_stop_callbacks() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
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
    assert [row.tick_index for row in result.completed_results] == [0, 1]


def test_tick_runner_preserves_step_reported_presentation_plan_ms() -> None:
    class _MeasuredSession:
        def timing_for_dt(self, dt: float) -> FrameTiming:
            return _timing(dt)

        def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False, commands: tuple = ()) -> _FakeTick:
            _ = timing, inputs, trace_rng, commands
            return _FakeTick(presentation_plan_ms=2.75)

    runner = TickRunner(
        session=_MeasuredSession(),
        input_provider=_FixedInputProvider(),
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
    assert result.completed_results[0].presentation_plan_ms == pytest.approx(2.75)
