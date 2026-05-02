from __future__ import annotations

from collections.abc import Callable

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    GameCommand,
    InputProvider,
    InputStatus,
    ResolvedTick,
    TickSupply,
)


class CallbackInputProvider(InputProvider):
    def __init__(
        self,
        *,
        resolve_tick: Callable[[int, float], ResolvedTick | None] | None = None,
        submit_command: Callable[[GameCommand], None] | None = None,
    ) -> None:
        self._resolve_tick = resolve_tick
        self._submit_command = submit_command

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        if self._resolve_tick is None:
            return TickSupply(status=InputStatus.STALLED, tick=None)
        resolved_tick = self._resolve_tick(int(tick_index), float(default_dt_seconds))
        if resolved_tick is None:
            return TickSupply(status=InputStatus.STALLED, tick=None)
        return TickSupply(status=InputStatus.READY, tick=resolved_tick)

    def supports_command_submission(self) -> bool:
        return self._submit_command is not None

    def submit_command(self, command: GameCommand) -> None:
        submit_command = self._submit_command
        if submit_command is not None:
            submit_command(command)


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
