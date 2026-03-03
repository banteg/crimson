from __future__ import annotations

from collections.abc import Callable
from typing import Generic, Protocol, TypeVar

import msgspec

from .clock import FixedStepClock
from .hooks import TickContext, TickHashes, TickHookBus, TickResult
from .input import PlayerInput
from .input_providers import InputProvider


class TickStepPayload(Protocol):
    command_hash: str
    dt_sim: float
    presentation: object


class TickPayload(Protocol):
    step: TickStepPayload


TimingT = TypeVar("TimingT")
TickT = TypeVar("TickT", bound=TickPayload)


def _extract_tick_payload(*, tick_index: int, tick: TickPayload) -> tuple[TickStepPayload, str, float, object]:
    try:
        step = tick.step
    except AttributeError as exc:
        raise TypeError(f"tick payload missing required field 'step' at tick {tick_index}") from exc
    try:
        command_hash_raw = step.command_hash
    except AttributeError as exc:
        raise TypeError(f"tick step missing required field 'command_hash' at tick {tick_index}") from exc
    try:
        dt_sim_raw = step.dt_sim
    except AttributeError as exc:
        raise TypeError(f"tick step missing required field 'dt_sim' at tick {tick_index}") from exc
    try:
        presentation = step.presentation
    except AttributeError as exc:
        raise TypeError(f"tick step missing required field 'presentation' at tick {tick_index}") from exc
    return (
        step,
        command_hash_raw,
        dt_sim_raw,
        presentation,
    )


class TickSession(Protocol[TimingT, TickT]):
    def timing_for_dt(self, dt: float) -> TimingT: ...

    def step_tick(self, *, timing: TimingT, inputs: list[PlayerInput] | None) -> TickT: ...


class TickRunnerConfig(msgspec.Struct, frozen=True):
    tick_rate: int = 60
    session_kind: str = ""
    mode_id: str = ""
    is_networked: bool = False
    is_replay: bool = False


class TickBatchResult(msgspec.Struct):
    ticks_completed: int = 0
    stalled: bool = False
    remaining_debt_ticks: int = 0
    presentation_plans: list[object] = msgspec.field(default_factory=list)


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
        on_tick_complete: Callable[[int, TickT], bool] | None = None,
    ) -> TickBatchResult:
        self._input_provider.begin_frame()
        self._frame_index += 1

        candidate_ticks = self._clock.advance(dt_seconds)
        if max_ticks is not None:
            candidate_ticks = min(candidate_ticks, max(0, max_ticks))
        if candidate_ticks <= 0:
            return TickBatchResult(
                ticks_completed=0,
                stalled=False,
                remaining_debt_ticks=int((self._clock.accum + 1e-9) / self._clock.dt_tick),
                presentation_plans=[],
            )

        ticks_completed = 0
        stalled = False
        plans: list[object] = []

        for _ in range(candidate_ticks):
            tick_index = self._next_tick_index
            tick_ctx = TickContext(
                tick_index=tick_index,
                dt_seconds=self._clock.dt_tick,
                inputs_present=False,
                session_kind=self._config.session_kind,
                mode_id=self._config.mode_id,
                is_networked=self._config.is_networked,
                is_replay=self._config.is_replay,
                inputs=None,
            )
            self._hook_bus.on_tick_begin(tick_ctx)
            inputs = self._input_provider.pull_tick_input(tick_index)
            if inputs is None:
                stalled = True
                self._hook_bus.on_tick_stall(tick_ctx)
                break

            ready_ctx = TickContext(
                tick_index=tick_index,
                dt_seconds=self._clock.dt_tick,
                inputs_present=True,
                session_kind=self._config.session_kind,
                mode_id=self._config.mode_id,
                is_networked=self._config.is_networked,
                is_replay=self._config.is_replay,
                inputs=list(inputs),
            )
            self._hook_bus.on_pre_sim(ready_ctx)

            timing = self._session.timing_for_dt(self._clock.dt_tick)
            tick = self._session.step_tick(
                timing=timing,
                inputs=inputs,
            )
            step, command_hash, dt_sim, presentation = _extract_tick_payload(
                tick_index=tick_index,
                tick=tick,
            )
            result = TickResult(
                tick_index=tick_index,
                command_hash=command_hash,
                dt_sim=dt_sim,
                payload=tick,
            )
            self._hook_bus.on_world_step_done(ready_ctx, result)
            self._hook_bus.on_pre_hash(ready_ctx, result)
            self._hook_bus.on_post_hash(
                ready_ctx,
                TickHashes(
                    command_hash=command_hash,
                    state_hash=None,
                ),
            )
            self._hook_bus.on_post_presentation(ready_ctx, result)
            should_stop = False
            if on_tick_complete is not None and on_tick_complete(tick_index, tick):
                should_stop = True
            self._hook_bus.on_tick_end(ready_ctx, result)
            plans.append(presentation)
            ticks_completed += 1
            self._next_tick_index += 1
            if should_stop:
                break

        unconsumed_ticks = candidate_ticks - ticks_completed
        if stalled and unconsumed_ticks > 0:
            self._clock.accum += unconsumed_ticks * self._clock.dt_tick

        remaining_debt_ticks = int((self._clock.accum + 1e-9) / self._clock.dt_tick)
        return TickBatchResult(
            ticks_completed=ticks_completed,
            stalled=stalled,
            remaining_debt_ticks=remaining_debt_ticks,
            presentation_plans=list(plans),
        )
