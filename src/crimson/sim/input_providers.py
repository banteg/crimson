from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import Enum
from typing import Protocol, TypeAlias

import msgspec

from ..local_input import clear_input_edges
from .input import PlayerInput


class PerkMenuOpenCommand(msgspec.Struct, tag="perk_menu_open", frozen=True):
    player_index: int


class PerkPickCommand(msgspec.Struct, tag="perk_pick", frozen=True):
    player_index: int
    choice_index: int


GameCommand: TypeAlias = PerkMenuOpenCommand | PerkPickCommand


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


class TickInput(msgspec.Struct, frozen=True):
    status: InputStatus
    inputs: list[PlayerInput] = msgspec.field(default_factory=list)


class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def pull_tick_input(self, tick_index: int) -> TickInput: ...

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]: ...

    def supports_commands(self) -> bool: ...

    def push_command(self, command: GameCommand) -> None: ...

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float: ...


TickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
TickCommandResolver: TypeAlias = Callable[[int], Sequence[GameCommand] | None]
TickCommandSubmitter: TypeAlias = Callable[[GameCommand], None]
LocalInputBuilder: TypeAlias = Callable[[FrameContext], Sequence[PlayerInput]]


class LocalInputProvider:
    """Adapter over local input polling."""

    def __init__(
        self,
        *,
        player_count: int,
        build_inputs: LocalInputBuilder,
    ) -> None:
        self._player_count = max(0, player_count)
        self._build_inputs = build_inputs
        self._pending_commands: list[GameCommand] = []
        self._commands_for_next_tick: list[GameCommand] = []
        self._frame_inputs: list[PlayerInput] = []
        self._edge_inputs: list[PlayerInput] = []
        self._first_tick_pending = False

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        frame_inputs = list(self._build_inputs(frame_ctx))
        self._frame_inputs = list(frame_inputs)
        self._edge_inputs = clear_input_edges(self._frame_inputs)
        self._first_tick_pending = True
        if self._pending_commands:
            self._commands_for_next_tick.extend(self._pending_commands)
            self._pending_commands.clear()

    def pull_tick_input(self, tick_index: int) -> TickInput:
        _ = tick_index
        if self._player_count <= 0:
            return TickInput(status=InputStatus.READY, inputs=[])
        if self._first_tick_pending:
            self._first_tick_pending = False
            return TickInput(status=InputStatus.READY, inputs=list(self._frame_inputs))
        return TickInput(status=InputStatus.READY, inputs=list(self._edge_inputs))

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        _ = tick_index
        if not self._commands_for_next_tick:
            return []
        commands = list(self._commands_for_next_tick)
        self._commands_for_next_tick.clear()
        return commands

    def supports_commands(self) -> bool:
        return True

    def push_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt


class NetworkInputProvider:
    """Runtime-backed input source; may stall when a tick is not ready yet."""

    def __init__(
        self,
        *,
        player_count: int,
        resolve_tick_input: TickInputResolver | None = None,
        resolve_tick_commands: TickCommandResolver | None = None,
        submit_command: TickCommandSubmitter | None = None,
    ) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input
        self._resolve_tick_commands = resolve_tick_commands
        self._submit_command = submit_command
        self._commands_by_tick: dict[int, list[GameCommand]] = {}

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> TickInput:
        resolver = self._resolve_tick_input
        if resolver is None:
            return TickInput(status=InputStatus.STALLED, inputs=[])
        inputs = resolver(tick_index)
        if inputs is None:
            return TickInput(status=InputStatus.STALLED, inputs=[])
        commands: list[GameCommand] = []
        resolve_commands = self._resolve_tick_commands
        if resolve_commands is not None:
            resolved_commands = resolve_commands(int(tick_index))
            if resolved_commands is not None:
                commands.extend(list(resolved_commands))
        if commands:
            self._queue_tick_commands(int(tick_index), commands)
        return TickInput(
            status=InputStatus.READY,
            inputs=list(inputs),
        )

    def supports_commands(self) -> bool:
        return self._submit_command is not None or self._resolve_tick_commands is not None

    def push_command(self, command: GameCommand) -> None:
        submit_command = self._submit_command
        if submit_command is not None:
            submit_command(command)

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        return self._commands_by_tick.pop(int(tick_index), [])

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt

    def _queue_tick_commands(self, tick_index: int, commands: list[GameCommand]) -> None:
        self._commands_by_tick.setdefault(int(tick_index), []).extend(commands)
