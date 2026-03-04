from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from ...net.lockstep_runtime import LockstepRuntime
from ...replay.types import PackedPlayerInput
from ...sim.sessions import DeterministicSessionStepTick

LanStepAction = Literal["continue", "stop_before_finalize", "stop_after_finalize"]


@dataclass(frozen=True, slots=True)
class LanTickStep:
    frame_tick_index: int
    frame_inputs: tuple[PackedPlayerInput, ...]
    tick: DeterministicSessionStepTick
    local_command_hash: str
    host_state_hash: str
    replay_tick_index: int | None


@dataclass(frozen=True, slots=True)
class LanFramePhase:
    role: str
    dt: float
    dt_ui_ms: float
    lockstep_runtime: LockstepRuntime | None
    session: object
    dt_tick: float


@dataclass(frozen=True, slots=True)
class LanTickPhase:
    role: str
    lockstep_runtime: LockstepRuntime | None
    session: object
    dt_tick: float


@dataclass(frozen=True, slots=True)
class LanTickAppliedPhase:
    role: str
    lockstep_runtime: LockstepRuntime | None
    session: object
    step: LanTickStep
    dt_tick: float


class LanModePolicy(Protocol):
    def prepare_frame(self, phase: LanFramePhase) -> bool: ...

    def before_tick_step(self, phase: LanTickPhase) -> None: ...

    def allow_frame_pop(self, phase: LanTickPhase) -> bool: ...

    def after_join_consume(self, phase: LanTickPhase) -> bool: ...

    def on_tick_applied(self, phase: LanTickAppliedPhase) -> LanStepAction: ...


class BaseLanModePolicy:
    def prepare_frame(self, phase: LanFramePhase) -> bool:
        _ = phase
        return True

    def before_tick_step(self, phase: LanTickPhase) -> None:
        _ = phase

    def allow_frame_pop(self, phase: LanTickPhase) -> bool:
        _ = phase
        return True

    def after_join_consume(self, phase: LanTickPhase) -> bool:
        _ = phase
        return False

    def on_tick_applied(self, phase: LanTickAppliedPhase) -> LanStepAction:
        _ = phase
        return "continue"
