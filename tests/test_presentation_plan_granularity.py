from __future__ import annotations

import msgspec

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputProvider
from crimson.sim.tick_runner import TickRunner


class _FakeStep(msgspec.Struct):
    command_hash: str
    dt_sim: float
    presentation: object
    presentation_plan_ms: float


class _FakeTick(msgspec.Struct):
    step: _FakeStep


class _SequencedSession:
    def __init__(self) -> None:
        self._tick_index = 0

    def timing_for_dt(self, dt: float) -> float:
        return float(dt)

    def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _FakeTick:
        _ = timing, inputs
        tick_index = int(self._tick_index)
        self._tick_index += 1
        return _FakeTick(
            step=_FakeStep(
                command_hash=f"h{tick_index}",
                dt_sim=1.0 / 60.0,
                presentation=f"plan-{tick_index}",
                presentation_plan_ms=0.0,
            ),
        )


class _ReadyInputProvider(InputProvider):
    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        return [PlayerInput()]

    def push_command(self, command) -> None:
        _ = command


def test_tick_runner_returns_per_tick_plans_in_frame_order() -> None:
    runner = TickRunner(
        session=_SequencedSession(),
        input_provider=_ReadyInputProvider(),
    )

    result = runner.advance_frame(2.0 / 60.0)

    assert result.ticks_completed == 2
    assert result.stalled is False
    assert result.presentation_plans == ["plan-0", "plan-1"]


def test_tick_runner_returns_empty_plans_when_no_ticks_advanced() -> None:
    runner = TickRunner(
        session=_SequencedSession(),
        input_provider=_ReadyInputProvider(),
    )

    result = runner.advance_frame(0.0)

    assert result.ticks_completed == 0
    assert result.presentation_plans == []
