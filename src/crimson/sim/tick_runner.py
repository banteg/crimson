from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import msgspec

from .clock import FixedStepClock
from .hooks import TickContext, TickHashes, TickHookBus, TickResult
from .input import PlayerInput
from .input_providers import FrameContext, InputProvider


class TickSession(Protocol):
    def timing_for_dt(self, dt: float) -> Any: ...

    def step_tick(self, *, timing: Any, inputs: list[PlayerInput] | None) -> Any: ...


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


class TickRunner:
    def __init__(
        self,
        *,
        session: TickSession,
        input_provider: InputProvider,
        hook_bus: TickHookBus | None = None,
        config: TickRunnerConfig | None = None,
    ) -> None:
        self._session = session
        self._input_provider = input_provider
        self._hook_bus = hook_bus if hook_bus is not None else TickHookBus()
        self._config = config if config is not None else TickRunnerConfig()
        self._clock = FixedStepClock(tick_rate=int(self._config.tick_rate))
        self._next_tick_index = 0
        self._frame_index = 0

    @property
    def clock(self) -> FixedStepClock:
        return self._clock

    @property
    def next_tick_index(self) -> int:
        return int(self._next_tick_index)

    def reset_clock(self) -> None:
        self._clock.reset()

    def advance_frame(
        self,
        dt_seconds: float,
        *,
        max_ticks: int | None = None,
        on_tick_complete: Callable[[int, object], bool] | None = None,
    ) -> TickBatchResult:
        self._input_provider.begin_frame(
            FrameContext(
                frame_index=int(self._frame_index),
                dt_seconds=float(dt_seconds),
                player_count=0,
                session_kind=str(self._config.session_kind),
                mode_id=str(self._config.mode_id),
                is_networked=bool(self._config.is_networked),
                is_replay=bool(self._config.is_replay),
            ),
        )
        self._frame_index += 1

        candidate_ticks = int(self._clock.advance(float(dt_seconds)))
        if max_ticks is not None:
            candidate_ticks = min(int(candidate_ticks), max(0, int(max_ticks)))
        if candidate_ticks <= 0:
            return TickBatchResult(
                ticks_completed=0,
                stalled=False,
                remaining_debt_ticks=int((self._clock.accum + 1e-9) / float(self._clock.dt_tick)),
                presentation_plans=[],
            )

        ticks_completed = 0
        stalled = False
        plans: list[object] = []

        for _ in range(int(candidate_ticks)):
            tick_index = int(self._next_tick_index)
            tick_ctx = TickContext(
                tick_index=int(tick_index),
                dt_seconds=float(self._clock.dt_tick),
                inputs_present=False,
                session_kind=str(self._config.session_kind),
                mode_id=str(self._config.mode_id),
                is_networked=bool(self._config.is_networked),
                is_replay=bool(self._config.is_replay),
            )
            self._hook_bus.on_tick_begin(tick_ctx)
            inputs = self._input_provider.pull_tick_input(int(tick_index))
            if inputs is None:
                stalled = True
                self._hook_bus.on_tick_stall(tick_ctx)
                break

            ready_ctx = TickContext(
                tick_index=int(tick_index),
                dt_seconds=float(self._clock.dt_tick),
                inputs_present=True,
                session_kind=str(self._config.session_kind),
                mode_id=str(self._config.mode_id),
                is_networked=bool(self._config.is_networked),
                is_replay=bool(self._config.is_replay),
            )
            self._hook_bus.on_pre_sim(ready_ctx)

            timing = self._session.timing_for_dt(float(self._clock.dt_tick))
            tick = self._session.step_tick(
                timing=timing,
                inputs=inputs,
            )
            step = getattr(tick, "step", tick)
            command_hash = str(getattr(step, "command_hash", ""))
            dt_sim = float(getattr(step, "dt_sim", 0.0))
            result = TickResult(
                tick_index=int(tick_index),
                command_hash=str(command_hash),
                dt_sim=float(dt_sim),
            )
            self._hook_bus.on_world_step_done(ready_ctx, result)
            self._hook_bus.on_pre_hash(ready_ctx, result)
            self._hook_bus.on_post_hash(
                ready_ctx,
                TickHashes(
                    command_hash=str(command_hash),
                    state_hash=None,
                ),
            )
            self._hook_bus.on_post_presentation(ready_ctx, result)
            self._hook_bus.on_tick_end(ready_ctx, result)

            plans.append(getattr(step, "presentation", None))
            ticks_completed += 1
            self._next_tick_index += 1
            if on_tick_complete is not None and bool(on_tick_complete(int(tick_index), tick)):
                break

        unconsumed_ticks = int(candidate_ticks) - int(ticks_completed)
        if stalled and unconsumed_ticks > 0:
            self._clock.accum += float(unconsumed_ticks) * float(self._clock.dt_tick)

        remaining_debt_ticks = int((self._clock.accum + 1e-9) / float(self._clock.dt_tick))
        return TickBatchResult(
            ticks_completed=int(ticks_completed),
            stalled=bool(stalled),
            remaining_debt_ticks=int(remaining_debt_ticks),
            presentation_plans=list(plans),
        )
