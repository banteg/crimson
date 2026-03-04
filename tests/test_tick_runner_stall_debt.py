from __future__ import annotations

import msgspec
import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputProvider, ReplayEndOfStream
from crimson.sim.tick_runner import TickRunner
from crimson.sim.timing import FrameTiming


class _FakeTick(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation_plan_ms: float = 0.0


def _timing(dt: float) -> FrameTiming:
    return FrameTiming(dt=dt, time_scale_active_entry=False, time_scale_factor=1.0, zero_gate_active=False, dt_sim=dt)


class _FakeSession:
    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _FakeTick:
        _ = timing, inputs, trace_rng
        return _FakeTick()


class _RowsInputProvider(InputProvider):
    def __init__(self, rows: dict[int, list[PlayerInput] | None]) -> None:
        self.rows = rows

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        return self.rows.get(int(tick_index))

    def push_command(self, command) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt


def test_tick_runner_stall_commits_completed_ticks_and_preserves_debt() -> None:
    provider = _RowsInputProvider(
        rows={
            0: [PlayerInput()],
            1: None,
        },
    )
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=provider,
    )

    first = runner.advance_frame(2.0 / 60.0)

    assert first.ticks_completed == 1
    assert first.stalled is True
    assert first.remaining_debt_ticks >= 1
    assert [result.command_hash for result in first.completed_results] == ["abc123"]
    assert runner.next_tick_index == 1

    provider.rows[1] = [PlayerInput()]
    # `FixedStepClock.advance` consumes debt only when dt > 0.
    second = runner.advance_frame(1e-6)

    assert second.ticks_completed == 1
    assert second.stalled is False
    assert second.remaining_debt_ticks == 0
    assert [result.command_hash for result in second.completed_results] == ["abc123"]
    assert runner.next_tick_index == 2


def test_tick_runner_replay_eos_preserves_completed_results_and_debt() -> None:
    class _ReplayRowsInputProvider(InputProvider):
        def begin_frame(self, frame_ctx: FrameContext) -> None:
            _ = frame_ctx
            return

        def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
            if int(tick_index) == 0:
                return [PlayerInput()]
            raise ReplayEndOfStream(f"replay input exhausted at tick {tick_index}")

        def push_command(self, command) -> None:
            _ = command

        def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
            return default_dt

    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_ReplayRowsInputProvider(),
    )

    with pytest.raises(ReplayEndOfStream) as exc_info:
        runner.advance_frame(2.0 / 60.0)

    exc = exc_info.value
    completed_results = getattr(exc, "completed_results")
    assert [result.command_hash for result in completed_results] == ["abc123"]
    assert int(getattr(exc, "ticks_completed")) == 1
    assert int(getattr(exc, "remaining_debt_ticks")) >= 1
    assert runner.next_tick_index == 1
