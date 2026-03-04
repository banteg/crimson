from __future__ import annotations

import inspect
from typing import Generic, Protocol, TypeVar

import msgspec

from .clock import FixedStepClock
from .hooks import TickContext, TickHashes, TickHookBus, TickResult
from .input import PlayerInput
from .input_providers import FrameContext, InputProvider


class TickStepPayload(Protocol):
    command_hash: str
    dt_sim: float
    presentation: object
    presentation_plan_ms: float


class TickPayload(Protocol):
    step: TickStepPayload


TimingT = TypeVar("TimingT")
TickT = TypeVar("TickT", bound=TickPayload)


class TickSession(Protocol[TimingT, TickT]):
    def timing_for_dt(self, dt: float) -> TimingT: ...

    def step_tick(self, *, timing: TimingT, inputs: list[PlayerInput] | None) -> TickT: ...


class TickRunnerConfig(msgspec.Struct, frozen=True):
    tick_rate: int = 60
    is_networked: bool = False
    is_replay: bool = False
    trace_rng: bool = False


class TickBatchResult(msgspec.Struct):
    ticks_completed: int = 0
    stalled: bool = False
    remaining_debt_ticks: int = 0
    completed_results: list[TickResult] = msgspec.field(default_factory=list)


class TickRunner(Generic[TimingT, TickT]):
    def __init__(
        self,
        *,
        session: TickSession[TimingT, TickT],
        input_provider: InputProvider,
        hook_bus: TickHookBus | None = None,
        config: TickRunnerConfig | None = None,
    ) -> None:
        self._session = session
        self._input_provider = input_provider
        self._hook_bus = hook_bus if hook_bus is not None else TickHookBus()
        self._config = config if config is not None else TickRunnerConfig()
        self._clock = FixedStepClock(tick_rate=self._config.tick_rate)
        self._next_tick_index = 0
        self._frame_index = 0
        self._step_accepts_trace_rng = "trace_rng" in inspect.signature(self._session.step_tick).parameters

    @property
    def clock(self) -> FixedStepClock:
        return self._clock

    @property
    def next_tick_index(self) -> int:
        return self._next_tick_index

    def reset_clock(self) -> None:
        self._clock.reset()

    def advance_frame(
        self,
        dt_seconds: float,
        *,
        max_ticks: int | None = None,
    ) -> TickBatchResult:
        self._frame_index += 1

        candidate_ticks = self._clock.advance(dt_seconds)
        if max_ticks is not None:
            candidate_ticks = min(candidate_ticks, max(0, max_ticks))
        self._input_provider.begin_frame(
            FrameContext(
                dt_seconds=float(dt_seconds),
                tick_dt_seconds=float(self._clock.dt_tick),
                frame_index=int(self._frame_index),
                candidate_ticks=int(candidate_ticks),
                is_networked=bool(self._config.is_networked),
                is_replay=bool(self._config.is_replay),
            ),
        )
        if candidate_ticks <= 0:
            return TickBatchResult(
                ticks_completed=0,
                stalled=False,
                remaining_debt_ticks=int((self._clock.accum + 1e-9) / self._clock.dt_tick),
                completed_results=[],
            )

        ticks_completed = 0
        stalled = False
        stopped_early = False
        completed_results: list[TickResult] = []

        for _ in range(candidate_ticks):
            tick_index = self._next_tick_index
            inputs = self._input_provider.pull_tick_input(tick_index)
            tick_inputs: list[PlayerInput] | None = inputs
            tick_dt_seconds = float(self._clock.dt_tick)
            resolve_tick_dt = getattr(self._input_provider, "resolve_tick_dt", None)
            if callable(resolve_tick_dt):
                tick_dt_seconds = float(resolve_tick_dt(int(tick_index), float(tick_dt_seconds)))
            tick_ctx = TickContext(
                tick_index=tick_index,
                dt_seconds=float(tick_dt_seconds),
                inputs_present=tick_inputs is not None,
                is_networked=self._config.is_networked,
                is_replay=self._config.is_replay,
                inputs=tick_inputs,
            )
            self._hook_bus.on_tick_begin(tick_ctx)
            if tick_inputs is None:
                stalled = True
                self._hook_bus.on_tick_stall(tick_ctx)
                break

            self._hook_bus.on_pre_sim(tick_ctx)

            timing = self._session.timing_for_dt(float(tick_dt_seconds))
            if self._step_accepts_trace_rng:
                tick = self._session.step_tick(
                    timing=timing,
                    inputs=tick_inputs,
                    trace_rng=bool(self._config.trace_rng),
                )
            else:
                tick = self._session.step_tick(
                    timing=timing,
                    inputs=tick_inputs,
                )
            step = tick.step
            command_hash = step.command_hash
            dt_sim = step.dt_sim
            result = TickResult(
                tick_index=tick_index,
                command_hash=command_hash,
                dt_sim=dt_sim,
                presentation_plan_ms=step.presentation_plan_ms,
                payload=tick,
            )
            self._hook_bus.on_world_step_done(tick_ctx, result)
            self._hook_bus.on_pre_hash(tick_ctx, result)
            self._hook_bus.on_post_hash(
                tick_ctx,
                TickHashes(
                    command_hash=command_hash,
                    state_hash=None,
                ),
            )
            self._hook_bus.on_post_presentation(tick_ctx, result)
            should_stop = bool(self._hook_bus.on_tick_end(tick_ctx, result))
            completed_results.append(result)
            ticks_completed += 1
            self._next_tick_index += 1
            if should_stop:
                stopped_early = True
                break

        unconsumed_ticks = candidate_ticks - ticks_completed
        if (stalled or stopped_early) and unconsumed_ticks > 0:
            self._clock.accum += unconsumed_ticks * self._clock.dt_tick

        remaining_debt_ticks = int((self._clock.accum + 1e-9) / self._clock.dt_tick)
        return TickBatchResult(
            ticks_completed=ticks_completed,
            stalled=stalled,
            remaining_debt_ticks=remaining_debt_ticks,
            completed_results=list(completed_results),
        )
