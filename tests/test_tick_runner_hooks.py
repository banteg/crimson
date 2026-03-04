from __future__ import annotations

import msgspec
import pytest

from crimson.sim.hooks import (
    CheckpointHook,
    NetworkSyncHook,
    ProfilerHook,
    ReplayRecorderHook,
    TickContext,
    TickHookBus,
    TickResult,
)
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, InputProvider
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

    def push_command(self, command) -> None:
        _ = command

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt


class _Recorder:
    def __init__(self) -> None:
        self.rows: list[list[PlayerInput]] = []

    def record_tick(self, inputs: list[PlayerInput]) -> int:
        self.rows.append(inputs)
        return len(self.rows) - 1


def test_tick_runner_concrete_hooks_record_and_emit() -> None:
    recorder = _Recorder()
    replay_hook = ReplayRecorderHook(recorder)
    checkpoint_rows: list[tuple[int, object]] = []
    hash_rows: list[tuple[int, str]] = []
    profiler = ProfilerHook()
    hook_bus = TickHookBus(
        [
            replay_hook,
            CheckpointHook(
                replay_recorder_hook=replay_hook,
                on_checkpoint=lambda tick_index, payload: checkpoint_rows.append((int(tick_index), payload)),
            ),
            NetworkSyncHook(on_hash=lambda tick_index, hashes: hash_rows.append((int(tick_index), str(hashes.command_hash)))),
            profiler,
        ],
    )
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
        hook_bus=hook_bus,
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert len(recorder.rows) == 1
    assert checkpoint_rows and checkpoint_rows[0][0] == 0
    assert hash_rows == [(0, "abc123")]
    assert profiler.sim_ms >= 0.0
    assert profiler.presentation_plan_ms >= 0.0
    assert profiler.presentation_apply_ms >= 0.0


def test_tick_runner_hook_stop_ends_frame_early() -> None:
    recorder = _Recorder()
    replay_hook = ReplayRecorderHook(recorder)
    checkpoint_rows: list[int] = []

    class _StopAfterFirstTickHook:
        def __init__(self) -> None:
            self.stop_count = 0

        def on_tick_end(self, _ctx: TickContext, _result: TickResult) -> bool:
            self.stop_count += 1
            return True

    stop_hook = _StopAfterFirstTickHook()
    hook_bus = TickHookBus(
        [
            replay_hook,
            CheckpointHook(
                replay_recorder_hook=replay_hook,
                on_checkpoint=lambda tick_index, _payload: checkpoint_rows.append(int(tick_index)),
            ),
            NetworkSyncHook(),
            ProfilerHook(),
            stop_hook,
        ],
    )
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
        hook_bus=hook_bus,
    )

    result = runner.advance_frame(2.0 / 60.0)

    assert result.ticks_completed == 1
    assert checkpoint_rows == [0]
    assert stop_hook.stop_count == 1


def test_profiler_hook_uses_step_reported_presentation_plan_time() -> None:
    class _MeasuredSession:
        def timing_for_dt(self, dt: float) -> FrameTiming:
            return _timing(dt)

        def step_tick(self, *, timing: FrameTiming, inputs: list[PlayerInput] | None, trace_rng: bool = False) -> _FakeTick:
            _ = timing, inputs, trace_rng
            return _FakeTick(presentation_plan_ms=2.75)

    profiler = ProfilerHook()
    runner = TickRunner(
        session=_MeasuredSession(),
        input_provider=_FixedInputProvider(),
        hook_bus=TickHookBus([profiler]),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert profiler.presentation_plan_ms == pytest.approx(2.75)
