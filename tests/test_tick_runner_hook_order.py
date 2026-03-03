from __future__ import annotations

import msgspec
import pytest

from crimson.sim.hooks import TickHashes, TickHookBus, TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputProvider
from crimson.sim.tick_runner import TickRunner


class _FakeStep(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation: object = "presentation-plan"


class _FakeTick(msgspec.Struct):
    step: _FakeStep = msgspec.field(default_factory=_FakeStep)


class _FakeSession:
    def timing_for_dt(self, dt: float) -> float:
        return float(dt)

    def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _FakeTick:
        _ = timing, inputs
        return _FakeTick()


class _MissingStepTick(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation: object = "presentation-plan"


class _MissingPresentationStep(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0


class _TickWithMissingPresentationStep(msgspec.Struct):
    step: _MissingPresentationStep = msgspec.field(default_factory=_MissingPresentationStep)


class _FixedInputProvider(InputProvider):
    def __init__(self, *, rows: dict[int, list[PlayerInput] | None]) -> None:
        self._rows = rows

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        return self._rows.get(int(tick_index), [PlayerInput()])

    def push_command(self, command) -> None:
        _ = command


class _RecorderHook:
    def __init__(self) -> None:
        self.events: list[str] = []

    def on_tick_begin(self, ctx) -> None:
        _ = ctx
        self.events.append("on_tick_begin")

    def on_tick_stall(self, ctx) -> None:
        _ = ctx
        self.events.append("on_tick_stall")

    def on_pre_sim(self, ctx) -> None:
        _ = ctx
        self.events.append("on_pre_sim")

    def on_world_step_done(self, ctx, result: TickResult) -> None:
        _ = ctx, result
        self.events.append("on_world_step_done")

    def on_pre_hash(self, ctx, result: TickResult) -> None:
        _ = ctx, result
        self.events.append("on_pre_hash")

    def on_post_hash(self, ctx, hashes: TickHashes) -> None:
        _ = ctx, hashes
        self.events.append("on_post_hash")

    def on_post_presentation(self, ctx, result: TickResult) -> None:
        _ = ctx, result
        self.events.append("on_post_presentation")

    def on_tick_end(self, ctx, result: TickResult) -> None:
        _ = ctx, result
        self.events.append("on_tick_end")


def test_tick_runner_hook_order_for_completed_tick() -> None:
    hook = _RecorderHook()
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
        hook_bus=TickHookBus([hook]),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert result.stalled is False
    assert hook.events == [
        "on_tick_begin",
        "on_pre_sim",
        "on_world_step_done",
        "on_pre_hash",
        "on_post_hash",
        "on_post_presentation",
        "on_tick_end",
    ]


def test_tick_runner_stall_invokes_stall_hook_only() -> None:
    hook = _RecorderHook()
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(rows={0: None}),
        hook_bus=TickHookBus([hook]),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 0
    assert result.stalled is True
    assert result.remaining_debt_ticks >= 1
    assert hook.events == [
        "on_tick_begin",
        "on_tick_stall",
    ]


def test_tick_runner_fails_fast_when_step_payload_missing() -> None:
    class _SessionMissingStep:
        def timing_for_dt(self, dt: float) -> float:
            return float(dt)

        def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _MissingStepTick:
            _ = timing, inputs
            return _MissingStepTick()

    runner = TickRunner(
        session=_SessionMissingStep(),
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
    )

    with pytest.raises(TypeError, match="missing required field 'step'"):
        runner.advance_frame(1.0 / 60.0)


def test_tick_runner_fails_fast_when_step_presentation_missing() -> None:
    class _SessionMissingPresentation:
        def timing_for_dt(self, dt: float) -> float:
            return float(dt)

        def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _TickWithMissingPresentationStep:
            _ = timing, inputs
            return _TickWithMissingPresentationStep()

    runner = TickRunner(
        session=_SessionMissingPresentation(),
        input_provider=_FixedInputProvider(rows={0: [PlayerInput()]}),
    )

    with pytest.raises(TypeError, match="missing required field 'presentation'"):
        runner.advance_frame(1.0 / 60.0)
