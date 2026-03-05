from __future__ import annotations

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import FrameContext, GameCommand, InputProvider, InputStatus, TickInput


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

    def pull_tick_input(self, tick_index: int) -> TickInput:
        row = self._rows.get(int(tick_index), [PlayerInput()])
        if row is None:
            return TickInput(status=InputStatus.STALLED, inputs=[])
        return TickInput(status=InputStatus.READY, inputs=list(row))

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        return []

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command: GameCommand) -> None:
        pass

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt


class EOSInputProvider(InputProvider):
    """Input provider that returns READY for tick 0 then EOS for all others."""

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        pass

    def pull_tick_input(self, tick_index: int) -> TickInput:
        if int(tick_index) == 0:
            return TickInput(status=InputStatus.READY, inputs=[PlayerInput()])
        return TickInput(status=InputStatus.EOS, inputs=[])

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        return []

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command: GameCommand) -> None:
        pass

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt
