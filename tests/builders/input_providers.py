from __future__ import annotations

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    GameCommand,
    InputProvider,
    InputStatus,
    ResolvedTick,
    TickSupply,
)


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
                inputs=list(row),
                commands=[],
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
                    inputs=[PlayerInput()],
                    commands=[],
                ),
            )
        return TickSupply(status=InputStatus.EOS, tick=None)

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        pass
