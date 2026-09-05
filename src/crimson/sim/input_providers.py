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


type GameCommand = PerkMenuOpenCommand | PerkPickCommand | TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand

type ReplayPreludeOperation = GameFrameRngAdvanceOperation | PerkMenuOpenCommand | PerkPickCommand
type ReplayPostludeOperation = PerkMenuOpenCommand
type ReplayTickCommand = TypoCharCommand | TypoBackspaceCommand | TypoSubmitCommand


class FrameContext(msgspec.Struct, frozen=True):
    dt_seconds: float
    tick_dt_seconds: float
    frame_index: int
    candidate_ticks: int
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
        self._frame_inputs: list[PlayerInput] = []

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        # Retain unconsumed edges across zero-tick frames while refreshing held
        # controls and aim. pull_tick clears only the edges it actually delivers.
        frame_inputs = self._runtime.capture_frame_inputs(frame_ctx)
        pending = self._frame_inputs
        self._frame_inputs = []
        for index, current in enumerate(frame_inputs):
            previous = pending[index] if index < len(pending) else PlayerInput()
            self._frame_inputs.append(
                msgspec.structs.replace(
                    current,
                    fire_pressed=current.fire_pressed or previous.fire_pressed,
                    reload_pressed=current.reload_pressed or previous.reload_pressed,
                    move_to_cursor_pressed=current.move_to_cursor_pressed or previous.move_to_cursor_pressed,
                ),
            )

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        # A press is a one-tick firing action even when the source has no held
        # state (mouse wheel), or was released before a simulation tick ran.
        # Keep the sampled held state in the buffer so catch-up ticks do not
        # repeat that pulse. Replays record the resolved action as usual.
        inputs = () if self._player_count <= 0 else tuple(
            msgspec.structs.replace(inp, fire_down=True) if inp.fire_pressed and not inp.fire_down else inp
            for inp in self._frame_inputs
        )
        commands = tuple(self._pending_commands)
        self._pending_commands.clear()
        self._frame_inputs = clear_input_edges(self._frame_inputs)
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=tick_index,
                dt_seconds=default_dt_seconds,
                inputs=inputs,
                commands=commands,
            ),
        )

    def clear_pending_edges(self) -> None:
        self._frame_inputs = clear_input_edges(self._frame_inputs)

    def supports_command_submission(self) -> bool:
        return True

    def submit_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)
