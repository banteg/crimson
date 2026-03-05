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


class _MissingPresentationPlanMsTick(msgspec.Struct):
    dt_sim: float = 1.0 / 60.0


class _FixedInputProvider(InputProvider):
    def __init__(self, *, rows: dict[int, list[PlayerInput] | None]) -> None:
        self._rows = rows

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> TickInput:
        row = self._rows.get(int(tick_index), [PlayerInput()])
        if row is None:
            return TickInput(status=InputStatus.STALLED, inputs=[])
        return TickInput(status=InputStatus.READY, inputs=list(row))

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


def test_tick_runner_completed_tick_result_shape() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
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
    assert result.batch_status is InputStatus.READY
    assert len(result.completed_results) == 1
    tick = result.completed_results[0]
    assert tick.tick_index == 0
    assert tick.tick_index == 0
    assert tick.inputs is not None


def test_tick_runner_stall_sets_stalled_and_preserves_debt() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: None}),
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

    assert result.ticks_completed == 0
    assert result.batch_status is InputStatus.STALLED
    assert int((clock.accum + 1e-9) / float(clock.dt_tick)) >= 1


def test_tick_runner_fails_fast_when_tick_payload_attribute_missing() -> None:
    class _SessionMissingAttr:
        def timing_for_dt(self, dt: float) -> FrameTiming:
            return _timing(dt)

        def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False, commands: tuple = ()) -> _MissingPresentationPlanMsTick:
            _ = timing, inputs, trace_rng, commands
            return _MissingPresentationPlanMsTick()

    runner = TickRunner(
        session=_SessionMissingAttr(),  # type: ignore[arg-type]  # intentionally malformed
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
    )
    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0

    with pytest.raises(AttributeError, match="presentation_plan_ms"):
        _advance_with_clock(
            runner=runner,
            clock=clock,
            start_tick=next_tick_index,
            frame_index=frame_index,
            dt_seconds=1.0 / 60.0,
        )
