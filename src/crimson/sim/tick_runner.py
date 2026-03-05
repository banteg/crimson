from __future__ import annotations

from typing import Protocol

import msgspec

from .hooks import TickResult
from .input import PlayerInput
from .input_providers import FrameContext, GameCommand, InputProvider, InputStatus
from .timing import FrameTiming


class TickPayload(Protocol):
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
        commands: tuple[GameCommand, ...] = (),
    ) -> TickPayload: ...


class TickRunnerConfig(msgspec.Struct, frozen=True):
    trace_rng: bool = False


class TickBatchResult(msgspec.Struct):
    ticks_completed: int = 0
    batch_status: InputStatus = InputStatus.READY
    next_tick_index: int = 0
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

    def begin_frame(
        self,
        frame_ctx: FrameContext,
    ) -> None:
        self._input_provider.begin_frame(
            frame_ctx,
        )

    def advance_ticks(
        self,
        *,
        start_tick: int,
        ticks_requested: int,
        tick_dt: float,
    ) -> TickBatchResult:
        start_tick = int(start_tick)
        ticks_requested = max(0, int(ticks_requested))
        tick_dt = float(tick_dt)

        if tick_dt <= 0.0:
            raise ValueError("tick_dt must be positive")

        if ticks_requested <= 0:
            return TickBatchResult(
                ticks_completed=0,
                batch_status=InputStatus.READY,
                next_tick_index=int(start_tick),
                completed_results=[],
            )

        ticks_completed = 0
        batch_status = InputStatus.READY
        completed_results: list[TickResult] = []

        for tick_offset in range(ticks_requested):
            tick_index = int(start_tick + tick_offset)
            tick_input = self._input_provider.pull_tick_input(tick_index)
            status = tick_input.status
            if status is InputStatus.STALLED:
                batch_status = InputStatus.STALLED
                break
            if status is InputStatus.EOS:
                batch_status = InputStatus.EOS
                break

            tick_inputs = list(tick_input.inputs)
            tick_dt_seconds = self._input_provider.resolve_tick_dt(tick_index, tick_dt)
            commands = tuple(self._input_provider.pull_tick_commands(tick_index))

            # Snapshot list identity before stepping so replay recording can
            # happen later in frame-driver code with pre-step inputs.
            result_inputs: list[PlayerInput] | None = list(tick_inputs)

            timing = self._session.timing_for_dt(tick_dt_seconds)
            tick = self._session.step_tick(
                timing=timing,
                inputs=tick_inputs,
                trace_rng=self._config.trace_rng,
                commands=commands,
            )
            dt_sim = tick.dt_sim
            result = TickResult(
                tick_index=tick_index,
                dt_sim=dt_sim,
                presentation_plan_ms=tick.presentation_plan_ms,
                payload=tick,
                inputs=result_inputs,
                commands=commands,
            )
            completed_results.append(result)
            ticks_completed += 1

        return TickBatchResult(
            ticks_completed=ticks_completed,
            batch_status=batch_status,
            next_tick_index=int(start_tick) + int(ticks_completed),
            completed_results=list(completed_results),
        )
