from __future__ import annotations

from collections.abc import Callable

import msgspec

from .hooks import TickResult
from .input_providers import FrameContext, InputProvider, InputStatus, ResolvedTick
from .sessions import DeterministicSession


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
        session: DeterministicSession,
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
        after_tick: Callable[[TickResult], bool | None] | None = None,
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
            tick_supply = self._input_provider.pull_tick(tick_index, tick_dt)
            status = tick_supply.status
            if status is InputStatus.STALLED:
                if tick_supply.tick is not None:
                    raise RuntimeError("stalled tick supply must not carry a resolved tick")
                batch_status = InputStatus.STALLED
                break
            if status is InputStatus.EOS:
                if tick_supply.tick is not None:
                    raise RuntimeError("eos tick supply must not carry a resolved tick")
                batch_status = InputStatus.EOS
                break

            source_tick = self._validated_source_tick(tick_supply=tick_supply, expected_tick_index=tick_index)
            tick_inputs = list(source_tick.inputs)
            commands = list(source_tick.commands)

            tick = self._session.step_tick(
                dt=float(source_tick.dt_seconds),
                inputs=tick_inputs,
                trace_rng=self._config.trace_rng,
                commands=commands,
            )
            result = TickResult(
                source_tick=source_tick,
                payload=tick,
            )
            completed_results.append(result)
            ticks_completed += 1
            if after_tick is not None and after_tick(result) is False:
                break

        return TickBatchResult(
            ticks_completed=ticks_completed,
            batch_status=batch_status,
            next_tick_index=int(start_tick) + int(ticks_completed),
            completed_results=list(completed_results),
        )

    @staticmethod
    def _validated_source_tick(*, tick_supply, expected_tick_index: int) -> ResolvedTick:
        source_tick = tick_supply.tick
        if source_tick is None:
            raise RuntimeError("ready tick supply must carry a resolved tick")
        if int(source_tick.tick_index) != int(expected_tick_index):
            raise RuntimeError(
                f"resolved tick index mismatch: expected={int(expected_tick_index)} got={int(source_tick.tick_index)}",
            )
        dt_seconds = float(source_tick.dt_seconds)
        if dt_seconds <= 0.0:
            raise RuntimeError("resolved tick dt_seconds must be positive")
        if source_tick.prelude or source_tick.postlude:
            raise RuntimeError("TickRunner input providers cannot supply replay boundary operations")
        return source_tick
