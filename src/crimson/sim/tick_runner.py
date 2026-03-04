from __future__ import annotations

from typing import Protocol

import msgspec

from .clock import FixedStepClock
from .hooks import TickResult
from .input import PlayerInput
from .input_providers import FrameContext, InputProvider, InputStatus
from .timing import FrameTiming


class TickPayload(Protocol):
    command_hash: str
    dt_sim: float
    presentation_plan_ms: float


class TickSession(Protocol):
    def timing_for_dt(self, dt: float) -> FrameTiming: ...

    def step_tick(
        self,
        *,
        timing: FrameTiming,
        inputs: list[PlayerInput] | None,
        trace_rng: bool = False,
    ) -> TickPayload: ...


class TickRunnerConfig(msgspec.Struct, frozen=True):
    tick_rate: int = 60
    is_networked: bool = False
    is_replay: bool = False
    trace_rng: bool = False


class TickBatchResult(msgspec.Struct):
    ticks_completed: int = 0
    batch_status: InputStatus = InputStatus.READY
    remaining_debt_ticks: int = 0
    completed_results: list[TickResult] = msgspec.field(default_factory=list)


class TickRunner:
    def __init__(
        self,
        *,
        session: TickSession,
        input_provider: InputProvider,
        config: TickRunnerConfig | None = None,
    ) -> None:
        self._session = session
        self._input_provider = input_provider
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
    ) -> TickBatchResult:
        self._frame_index += 1

        candidate_ticks = self._clock.advance(dt_seconds)
        if max_ticks is not None:
            candidate_ticks = min(candidate_ticks, max(0, max_ticks))
        self._input_provider.begin_frame(
            FrameContext(
                dt_seconds=dt_seconds,
                tick_dt_seconds=self._clock.dt_tick,
                frame_index=self._frame_index,
                candidate_ticks=candidate_ticks,
                is_networked=self._config.is_networked,
                is_replay=self._config.is_replay,
            ),
        )
        if candidate_ticks <= 0:
            return TickBatchResult(
                ticks_completed=0,
                batch_status=InputStatus.READY,
                remaining_debt_ticks=int((self._clock.accum + 1e-9) / self._clock.dt_tick),
                completed_results=[],
            )

        ticks_completed = 0
        batch_status = InputStatus.READY
        completed_results: list[TickResult] = []

        for _ in range(candidate_ticks):
            tick_index = self._next_tick_index
            tick_input = self._input_provider.pull_tick_input(tick_index)
            status = tick_input.status
            if status is InputStatus.STALLED:
                batch_status = InputStatus.STALLED
                break
            if status is InputStatus.EOS:
                batch_status = InputStatus.EOS
                break

            tick_inputs = list(tick_input.inputs)
            tick_dt_seconds = self._input_provider.resolve_tick_dt(tick_index, self._clock.dt_tick)

            # Snapshot list identity before stepping so replay recording can
            # happen later in frame-driver code with pre-step inputs.
            result_inputs: list[PlayerInput] | None = list(tick_inputs)

            timing = self._session.timing_for_dt(tick_dt_seconds)
            tick = self._session.step_tick(
                timing=timing,
                inputs=tick_inputs,
                trace_rng=self._config.trace_rng,
            )
            command_hash = tick.command_hash
            dt_sim = tick.dt_sim
            result = TickResult(
                tick_index=tick_index,
                command_hash=command_hash,
                dt_sim=dt_sim,
                presentation_plan_ms=tick.presentation_plan_ms,
                payload=tick,
                inputs=result_inputs,
            )
            completed_results.append(result)
            ticks_completed += 1
            self._next_tick_index += 1

        unconsumed_ticks = candidate_ticks - ticks_completed
        if batch_status in (InputStatus.STALLED, InputStatus.EOS) and unconsumed_ticks > 0:
            self._clock.accum += unconsumed_ticks * self._clock.dt_tick

        remaining_debt_ticks = int((self._clock.accum + 1e-9) / self._clock.dt_tick)
        return TickBatchResult(
            ticks_completed=ticks_completed,
            batch_status=batch_status,
            remaining_debt_ticks=remaining_debt_ticks,
            completed_results=list(completed_results),
        )
