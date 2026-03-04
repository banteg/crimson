from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Protocol, TypeAlias, cast, runtime_checkable

import msgspec

if TYPE_CHECKING:
    from .input import PlayerInput


class TickContext(msgspec.Struct, frozen=True):
    tick_index: int
    dt_seconds: float
    inputs_present: bool
    is_networked: bool
    is_replay: bool
    inputs: list[PlayerInput] | None = None


class TickHashes(msgspec.Struct, frozen=True):
    command_hash: str
    state_hash: str | None = None


class TickResult(msgspec.Struct, frozen=True):
    tick_index: int
    command_hash: str
    dt_sim: float
    presentation_plan_ms: float = 0.0
    payload: object | None = None


# Hooks provide an explicit subset of tick callbacks through optional methods.
TickHook: TypeAlias = object


class TickHookBus:
    def __init__(self, hooks: Iterable[TickHook] | None = None) -> None:
        self._hooks: list[TickHook] = list(hooks or [])

    @property
    def hooks(self) -> tuple[TickHook, ...]:
        return tuple(self._hooks)

    def add_hook(self, hook: TickHook) -> None:
        self._hooks.append(hook)

    @staticmethod
    def _resolve_method(hook: TickHook, method_name: str) -> Callable[..., object] | None:
        method = getattr(hook, method_name, None)
        if method is None:
            return None
        if not callable(method):
            raise TypeError(f"{type(hook).__name__}.{method_name} must be callable")
        return cast(Callable[..., object], method)

    def _dispatch(self, method_name: str, *args: object) -> None:
        for hook in self._hooks:
            method = self._resolve_method(hook, method_name)
            if method is None:
                continue
            method(*args)

    def on_tick_begin(self, ctx: TickContext) -> None:
        self._dispatch("on_tick_begin", ctx)

    def on_tick_stall(self, ctx: TickContext) -> None:
        self._dispatch("on_tick_stall", ctx)

    def on_pre_sim(self, ctx: TickContext) -> None:
        self._dispatch("on_pre_sim", ctx)

    def on_world_step_done(self, ctx: TickContext, result: TickResult) -> None:
        self._dispatch("on_world_step_done", ctx, result)

    def on_pre_hash(self, ctx: TickContext, result: TickResult) -> None:
        self._dispatch("on_pre_hash", ctx, result)

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None:
        self._dispatch("on_post_hash", ctx, hashes)

    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None:
        self._dispatch("on_post_presentation", ctx, result)

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> bool:
        should_stop = False
        for hook in self._hooks:
            method = self._resolve_method(hook, "on_tick_end")
            if method is None:
                continue
            if bool(method(ctx, result)):
                should_stop = True
        return should_stop


@runtime_checkable
class ReplayRecorder(Protocol):
    def record_tick(self, inputs: list[PlayerInput]) -> int: ...


class ReplayRecorderHook:
    def __init__(self, recorder: ReplayRecorder | None) -> None:
        self._recorder = recorder
        self.recorded_tick_by_runner_tick: dict[int, int] = {}

    def set_recorder(self, recorder: ReplayRecorder | None) -> None:
        self._recorder = recorder

    def clear_recorded_ticks(self) -> None:
        self.recorded_tick_by_runner_tick.clear()

    def on_pre_sim(self, ctx: TickContext) -> None:
        recorder = self._recorder
        if recorder is None:
            return
        if not ctx.inputs_present or ctx.inputs is None:
            return
        inputs = ctx.inputs
        tick_index = recorder.record_tick(inputs)
        self.recorded_tick_by_runner_tick[ctx.tick_index] = tick_index


class CheckpointHook:
    def __init__(
        self,
        *,
        replay_recorder_hook: ReplayRecorderHook,
        on_checkpoint: Callable[[int, object], None] | None = None,
    ) -> None:
        self._replay_recorder_hook = replay_recorder_hook
        self._on_checkpoint = on_checkpoint

    def set_on_checkpoint(self, callback: Callable[[int, object], None] | None) -> None:
        self._on_checkpoint = callback

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None:
        callback = self._on_checkpoint
        if callback is None:
            return
        replay_tick = self._replay_recorder_hook.recorded_tick_by_runner_tick.pop(ctx.tick_index, None)
        if replay_tick is None:
            return
        payload = result.payload
        if payload is None:
            return
        callback(replay_tick, payload)


class NetworkSyncHook:
    def __init__(self, *, on_hash: Callable[[int, TickHashes], None] | None = None) -> None:
        self._on_hash = on_hash
        self.recorded_hashes_by_runner_tick: dict[int, TickHashes] = {}

    def set_on_hash(self, callback: Callable[[int, TickHashes], None] | None) -> None:
        self._on_hash = callback

    def clear_recorded_hashes(self) -> None:
        self.recorded_hashes_by_runner_tick.clear()

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None:
        self.recorded_hashes_by_runner_tick[ctx.tick_index] = hashes
        callback = self._on_hash
        if callback is None:
            return
        callback(ctx.tick_index, hashes)


class ProfilerHook:
    def __init__(self) -> None:
        self.sim_ms = 0.0
        self.presentation_plan_ms = 0.0
        self.presentation_apply_ms = 0.0
        self._sim_ns_start = 0
        self._apply_ns_start = 0

    @staticmethod
    def _now_ns() -> int:
        return time.perf_counter_ns()

    def on_pre_sim(self, ctx: TickContext) -> None:
        _ = ctx
        self._sim_ns_start = self._now_ns()

    def on_world_step_done(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx
        if self._sim_ns_start > 0:
            self.sim_ms += (self._now_ns() - self._sim_ns_start) / 1_000_000.0
            self._sim_ns_start = 0
        self.presentation_plan_ms += max(0.0, float(result.presentation_plan_ms))

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None:
        _ = ctx, hashes
        self._apply_ns_start = self._now_ns()

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx, result
        if self._apply_ns_start > 0:
            self.presentation_apply_ms += (self._now_ns() - self._apply_ns_start) / 1_000_000.0
            self._apply_ns_start = 0
