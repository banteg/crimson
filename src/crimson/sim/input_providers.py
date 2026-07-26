from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from typing import Annotated, Protocol

import msgspec

from ..local_input import clear_input_edges
from .input import PlayerInput

type TypoChar = Annotated[str, msgspec.Meta(min_length=1, max_length=1)]


class PerkMenuOpenCommand(msgspec.Struct, tag="perk_menu_open", frozen=True, forbid_unknown_fields=True):
    player_index: int


class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True, forbid_unknown_fields=True):
    player_index: int
    choice_index: int


class GameFrameRngAdvanceOperation(
    msgspec.Struct,
    tag="game_frame_rng_advance",
    frozen=True,
    forbid_unknown_fields=True,
):
    """Advance the native top-level frame RNG side effect for skipped frames."""

    frames: int


class TypoCharCommand(msgspec.Struct, tag="typo_char", frozen=True, forbid_unknown_fields=True):
    player_index: int
    ch: TypoChar


class TypoBackspaceCommand(msgspec.Struct, tag="typo_backspace", frozen=True, forbid_unknown_fields=True):
    player_index: int


class TypoSubmitCommand(msgspec.Struct, tag="typo_submit", frozen=True, forbid_unknown_fields=True):
    player_index: int


type GameCommand = (
    PerkMenuOpenCommand | PerkPickCommand | TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand
)

type ReplayPreludeOperation = GameFrameRngAdvanceOperation | PerkMenuOpenCommand | PerkPickCommand
type ReplayPostludeOperation = PerkMenuOpenCommand
type ReplayTickCommand = TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand


class FrameContext(msgspec.Struct, frozen=True):
    dt_seconds: float
    tick_dt_seconds: float
    frame_index: int
    candidate_ticks: int
    is_networked: bool = False
    is_replay: bool = False


class InputStatus(str, Enum):
    READY = "ready"
    STALLED = "stalled"
    EOS = "eos"


class ResolvedTick(msgspec.Struct, frozen=True):
    tick_index: int
    dt_seconds: float
    inputs: tuple[PlayerInput, ...] = ()
    prelude: tuple[ReplayPreludeOperation, ...] = ()
    postlude: tuple[ReplayPostludeOperation, ...] = ()
    commands: tuple[GameCommand, ...] = ()


class TickSupply(msgspec.Struct, frozen=True):
    status: InputStatus
    tick: ResolvedTick | None = None


class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply: ...

    def supports_command_submission(self) -> bool: ...

    def submit_command(self, command: GameCommand) -> None: ...


class LocalInputRuntime(msgspec.Struct):
    def capture_frame_inputs(self, frame_ctx: FrameContext) -> Sequence[PlayerInput]:
        _ = frame_ctx
        raise NotImplementedError


class LocalInputProvider:
    """Adapter over local input polling."""

    def __init__(
        self,
        *,
        player_count: int,
        runtime: LocalInputRuntime,
    ) -> None:
        self._player_count = max(0, player_count)
        self._runtime = runtime
        self._pending_commands: list[GameCommand] = []
        self._commands_for_next_tick: list[GameCommand] = []
        self._frame_inputs: list[PlayerInput] = []
        self._edge_inputs: list[PlayerInput] = []
        self._first_tick_pending = False

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        frame_inputs = list(self._runtime.capture_frame_inputs(frame_ctx))
        self._frame_inputs = list(frame_inputs)
        self._edge_inputs = clear_input_edges(self._frame_inputs)
        self._first_tick_pending = True
        if self._pending_commands:
            self._commands_for_next_tick.extend(self._pending_commands)
            self._pending_commands.clear()

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        tick_index = int(tick_index)
        dt_seconds = float(default_dt_seconds)
        if self._first_tick_pending:
            self._first_tick_pending = False
            inputs = [] if self._player_count <= 0 else list(self._frame_inputs)
            commands = list(self._commands_for_next_tick)
            self._commands_for_next_tick.clear()
            return TickSupply(
                status=InputStatus.READY,
                tick=ResolvedTick(
                    tick_index=tick_index,
                    dt_seconds=dt_seconds,
                    inputs=tuple(inputs),
                    commands=tuple(commands),
                ),
            )
        inputs = [] if self._player_count <= 0 else list(self._edge_inputs)
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=tick_index,
                dt_seconds=dt_seconds,
                inputs=tuple(inputs),
                commands=(),
            ),
        )

    def supports_command_submission(self) -> bool:
        return True

    def submit_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)
