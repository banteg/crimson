from __future__ import annotations

import msgspec
import pytest

from crimson.sim.hooks import CheckpointHook, NetworkSyncHook, ProfilerHook, ReplayRecorderHook, TickHookBus
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import InputProvider
from crimson.sim.tick_runner import TickRunner


class _FakeStep(msgspec.Struct):
    command_hash: str = "abc123"
    dt_sim: float = 1.0 / 60.0
    presentation: object = "plan"
    presentation_plan_ms: float = 0.0


class _FakeTick(msgspec.Struct):
    step: _FakeStep = msgspec.field(default_factory=_FakeStep)


class _FakeSession:
    def timing_for_dt(self, dt: float) -> float:
        return float(dt)

    def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _FakeTick:
        _ = timing, inputs
        return _FakeTick()


class _FixedInputProvider(InputProvider):
    def begin_frame(self) -> None:
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        return [PlayerInput()]


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


def test_checkpoint_hook_fires_after_tick_complete_callback() -> None:
    recorder = _Recorder()
    replay_hook = ReplayRecorderHook(recorder)
    applied_flag = {"applied": False}
    checkpoint_seen_applied: list[bool] = []
    hook_bus = TickHookBus(
        [
            replay_hook,
            CheckpointHook(
                replay_recorder_hook=replay_hook,
                on_checkpoint=lambda _tick_index, _payload: checkpoint_seen_applied.append(bool(applied_flag["applied"])),
            ),
            NetworkSyncHook(),
            ProfilerHook(),
        ],
    )
    runner = TickRunner(
        session=_FakeSession(),
        input_provider=_FixedInputProvider(),
        hook_bus=hook_bus,
    )

    def _on_tick_complete(_tick_index: int, _tick: object) -> bool:
        applied_flag["applied"] = True
        return False

    result = runner.advance_frame(1.0 / 60.0, on_tick_complete=_on_tick_complete)

    assert result.ticks_completed == 1
    assert checkpoint_seen_applied == [True]


def test_profiler_hook_uses_step_reported_presentation_plan_time() -> None:
    class _MeasuredSession:
        def timing_for_dt(self, dt: float) -> float:
            return float(dt)

        def step_tick(self, *, timing: float, inputs: list[PlayerInput] | None) -> _FakeTick:
            _ = timing, inputs
            return _FakeTick(step=_FakeStep(presentation_plan_ms=2.75))

    profiler = ProfilerHook()
    runner = TickRunner(
        session=_MeasuredSession(),
        input_provider=_FixedInputProvider(),
        hook_bus=TickHookBus([profiler]),
    )

    result = runner.advance_frame(1.0 / 60.0)

    assert result.ticks_completed == 1
    assert profiler.presentation_plan_ms == pytest.approx(2.75)
