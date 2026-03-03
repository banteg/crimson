from __future__ import annotations

import msgspec

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputProvider
from crimson.sim.tick_runner import TickRunner


class _FakeStep(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation: object = "plan"


class _FakeTick(msgspec.Struct):
    step: _FakeStep = msgspec.field(default_factory=_FakeStep)


class _FakeSession:
    def timing_for_dt(self, dt: float) -> float:
        return float(dt)

    def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _FakeTick:
        _ = timing, inputs
        return _FakeTick()


class _RowsInputProvider(InputProvider):
    def __init__(self, rows: dict[int, list[PlayerInput] | None]) -> None:
        self.rows = rows

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        return self.rows.get(int(tick_index))

    def push_command(self, command) -> None:
        _ = command


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
    assert first.presentation_plans == ["plan"]
    assert runner.next_tick_index == 1

    provider.rows[1] = [PlayerInput()]
    # `FixedStepClock.advance` consumes debt only when dt > 0.
    second = runner.advance_frame(1e-6)

    assert second.ticks_completed == 1
    assert second.stalled is False
    assert second.remaining_debt_ticks == 0
    assert second.presentation_plans == ["plan"]
    assert runner.next_tick_index == 2
