from __future__ import annotations

import msgspec
import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputCommand, InputProvider, InputStatus, TickInput
from crimson.sim.tick_runner import TickRunner
from crimson.sim.timing import FrameTiming


class _FakeTick(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation_plan_ms: float = 0.0


def _timing(dt: float) -> FrameTiming:
    return FrameTiming(dt=dt, time_scale_active_entry=False, time_scale_factor=1.0, zero_gate_active=False, dt_sim=dt)


class _MissingPresentationPlanMsTick(msgspec.Struct):
    command_hash: str = "abc123"
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

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        _ = tick_index
        return []

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command: InputCommand) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        _ = tick_index
        return default_dt


class _FakeSession:
    def timing_for_dt(self, dt: float) -> FrameTiming:
        return _timing(dt)

    def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _FakeTick:
        _ = timing, inputs, trace_rng
        return _FakeTick()


def test_tick_runner_completed_tick_result_shape() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert result.batch_status is InputStatus.READY
    assert len(result.completed_results) == 1
    tick = result.completed_results[0]
    assert tick.tick_index == 0
    assert tick.command_hash == "abc123"
    assert tick.inputs is not None


def test_tick_runner_stall_sets_stalled_and_preserves_debt() -> None:
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: None}),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 0
    assert result.batch_status is InputStatus.STALLED
    assert result.remaining_debt_ticks >= 1


def test_tick_runner_fails_fast_when_tick_payload_attribute_missing() -> None:
    class _SessionMissingAttr:
        def timing_for_dt(self, dt: float) -> FrameTiming:
            return _timing(dt)

        def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _MissingPresentationPlanMsTick:
            _ = timing, inputs, trace_rng
            return _MissingPresentationPlanMsTick()

    runner = TickRunner(
        session=_SessionMissingAttr(),  # type: ignore[arg-type]  # intentionally malformed
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
    )

    with pytest.raises(AttributeError, match="presentation_plan_ms"):
        runner.advance_frame(1.0 / 60.0)
