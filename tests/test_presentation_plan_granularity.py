from __future__ import annotations

import msgspec

from crimson.sim.clock import FixedStepClock
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputCommand, InputProvider, InputStatus, TickInput
from crimson.sim.tick_runner import TickBatchResult, TickRunner
from crimson.sim.timing import FrameTiming


class _FakeTick(msgspec.Struct):
    command_hash: str
    dt_sim: float
    presentation_plan_ms: float


def _timing(dt: float) -> FrameTiming:
    return FrameTiming(dt=dt, time_scale_active_entry=False, time_scale_factor=1.0, zero_gate_active=False, dt_sim=dt)


class _SequencedSession:
    def __init__(self) -> None:
        self._tick_index = 0

    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _FakeTick:
        _ = timing, inputs, trace_rng
        tick_index = int(self._tick_index)
        self._tick_index += 1
        return _FakeTick(
            command_hash=f"h{tick_index}",
            dt_sim=1.0 / 60.0,
            presentation_plan_ms=0.0,
        )


class _ReadyInputProvider(InputProvider):
    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> TickInput:
        _ = tick_index
        return TickInput(status=InputStatus.READY, inputs=[PlayerInput()])

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        _ = tick_index
        return []

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt


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


def test_tick_runner_returns_per_tick_plans_in_frame_order() -> None:
    runner = TickRunner(
        session=_SequencedSession(),
        input_provider=_ReadyInputProvider(),
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
    assert [row.command_hash for row in result.completed_results] == ["h0", "h1"]


def test_tick_runner_returns_empty_plans_when_no_ticks_advanced() -> None:
    runner = TickRunner(
        session=_SequencedSession(),
        input_provider=_ReadyInputProvider(),
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
