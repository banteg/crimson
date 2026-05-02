from __future__ import annotations

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    GameCommand,
    InputProvider,
    InputStatus,
    LocalInputRuntime,
    ResolvedTick,
    TickSupply,
)


class StaticLocalInputRuntime(LocalInputRuntime):
    inputs: tuple[PlayerInput, ...] = ()

    def capture_frame_inputs(self, frame_ctx: FrameContext) -> tuple[PlayerInput, ...]:
        _ = frame_ctx
        return tuple(self.inputs)


class StalledInputProvider(InputProvider):
    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        _ = tick_index, default_dt_seconds
        return TickSupply(status=InputStatus.STALLED, tick=None)

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        _ = command


class ReadyTickInputProvider(InputProvider):
    def __init__(
        self,
        *,
        inputs: tuple[PlayerInput, ...] = (),
        commands: tuple[GameCommand, ...] = (),
        dt_seconds: float | None = None,
    ) -> None:
        self._inputs = inputs
        self._commands = commands
        self._dt_seconds = dt_seconds

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        dt_seconds = float(default_dt_seconds) if self._dt_seconds is None else float(self._dt_seconds)
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=int(tick_index),
                dt_seconds=dt_seconds,
                inputs=tuple(self._inputs),
                commands=tuple(self._commands),
            ),
        )

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        _ = command


class StallableInputProvider(InputProvider):
    """Input provider where each tick's readiness is configured via a dict.

    - Key present with a list → READY with those inputs
    - Key present with None → STALLED
    - Key missing → READY with a default PlayerInput
    """

    def __init__(self, rows: dict[int, list[PlayerInput] | None] | None = None) -> None:
        self._rows = rows or {}

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        pass

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        row = self._rows.get(int(tick_index), [PlayerInput()])
        if row is None:
            return TickSupply(status=InputStatus.STALLED, tick=None)
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=int(tick_index),
                dt_seconds=float(default_dt_seconds),
                inputs=tuple(row),
                commands=(),
            ),
        )

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        pass


class EOSInputProvider(InputProvider):
    """Input provider that returns READY for tick 0 then EOS for all others."""

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        pass

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        if int(tick_index) == 0:
            return TickSupply(
                status=InputStatus.READY,
                tick=ResolvedTick(
                    tick_index=int(tick_index),
                    dt_seconds=float(default_dt_seconds),
                    inputs=(PlayerInput(),),
                    commands=(),
                ),
            )
        return TickSupply(status=InputStatus.EOS, tick=None)

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        pass
