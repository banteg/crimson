from __future__ import annotations

import msgspec
import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputCommand, InputProvider
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


class _FixedInputProvider(InputProvider):
    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        return [PlayerInput()]

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        _ = tick_index
        return []

    def push_command(self, command: InputCommand) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        _ = tick_index
        return default_dt


def test_tick_runner_exposes_tick_inputs_for_explicit_replay_recording() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert len(result.completed_results) == 1
    assert result.completed_results[0].inputs is not None
    assert len(result.completed_results[0].inputs or []) == 1


def test_tick_runner_advances_all_candidate_ticks_without_hook_stop_callbacks() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
    )

    result = runner.advance_frame(2.0 / 60.0)

    assert result.ticks_completed == 2
    assert [row.tick_index for row in result.completed_results] == [0, 1]


def test_tick_runner_preserves_step_reported_presentation_plan_ms() -> None:
    class _MeasuredSession:
        def timing_for_dt(self, dt: float) -> FrameTiming:
            return _timing(dt)

        def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _FakeTick:
            _ = timing, inputs, trace_rng
            return _FakeTick(presentation_plan_ms=2.75)

    runner = TickRunner(
        session=_MeasuredSession(),
        input_provider=_FixedInputProvider(),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert result.completed_results[0].presentation_plan_ms == pytest.approx(2.75)
