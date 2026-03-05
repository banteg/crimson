from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import Enum
from typing import Protocol, TypeAlias

import msgspec

from ..local_input import clear_input_edges
from .input import PlayerInput
from .input_frame import normalize_input_frame


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


class ReplayJournal(Protocol):
    def read_tick_inputs(self, tick_index: int) -> Sequence[PlayerInput] | None: ...

    def read_tick_dt(self, tick_index: int, default_dt: float) -> float: ...

    def tick_count(self) -> int | None: ...


class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def pull_tick_input(self, tick_index: int) -> TickInput: ...

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]: ...

    def supports_commands(self) -> bool: ...

    def push_command(self, command: GameCommand) -> None: ...

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float: ...


TickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickDtResolver: TypeAlias = Callable[[int], float]
TickCommandResolver: TypeAlias = Callable[[int], Sequence[GameCommand] | None]
TickCommandEmitter: TypeAlias = Callable[[int, GameCommand], None]
LocalInputBuilder: TypeAlias = Callable[[FrameContext], Sequence[PlayerInput]]


def normalize_provider_tick_inputs(*, inputs: Sequence[PlayerInput], player_count: int) -> list[PlayerInput]:
    """Normalize provider output to a fixed player-index order."""

    count = max(0, player_count)
    if count > 0 and len(inputs) == 0:
        raise ValueError("empty input list is invalid when player_count > 0")
    return normalize_input_frame(inputs, player_count=count).as_list()


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
        self._frame_inputs = normalize_provider_tick_inputs(inputs=frame_inputs, player_count=self._player_count)
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


class ReplayInputProvider:
    """Deterministic adapter over recorded replay input rows."""

    def __init__(
        self,
        *,
        player_count: int,
        resolve_tick_input: ReplayTickInputResolver | None = None,
        tick_count: int | None = None,
        resolve_tick_dt: ReplayTickDtResolver | None = None,
        journal: ReplayJournal | None = None,
    ) -> None:
        if journal is not None and resolve_tick_input is not None:
            raise ValueError("ReplayInputProvider accepts either journal or resolve_tick_input, not both")
        if journal is None and resolve_tick_input is None:
            raise ValueError("ReplayInputProvider requires journal or resolve_tick_input")

        self._player_count = max(0, player_count)
        self._journal = journal
        self._resolve_tick_input = resolve_tick_input
        self._resolve_tick_dt = resolve_tick_dt
        journal_tick_count = journal.tick_count() if journal is not None else None
        resolved_tick_count = journal_tick_count if tick_count is None else tick_count
        self._tick_count = max(0, int(resolved_tick_count)) if resolved_tick_count is not None else None

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> TickInput:
        idx = tick_index
        if idx < 0:
            return TickInput(status=InputStatus.EOS, inputs=[])
        tick_count = self._tick_count
        if tick_count is not None and idx >= tick_count:
            return TickInput(status=InputStatus.EOS, inputs=[])
        journal = self._journal
        if journal is not None:
            resolved = journal.read_tick_inputs(idx)
        else:
            resolver = self._resolve_tick_input
            if resolver is None:
                return TickInput(status=InputStatus.EOS, inputs=[])
            resolved = resolver(idx)
        if resolved is None:
            return TickInput(status=InputStatus.EOS, inputs=[])
        row = list(resolved)
        return TickInput(
            status=InputStatus.READY,
            inputs=normalize_provider_tick_inputs(inputs=row, player_count=self._player_count),
        )

    def supports_commands(self) -> bool:
        return False

    def push_command(self, command: GameCommand) -> None:
        _ = command
        return

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        _ = tick_index
        return []

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        journal = self._journal
        if journal is not None:
            return float(journal.read_tick_dt(int(tick_index), float(default_dt)))
        resolver = self._resolve_tick_dt
        if resolver is None:
            return float(default_dt)
        return float(resolver(int(tick_index)))


class NetworkInputProvider:
    """Runtime-backed input source; may stall when a tick is not ready yet."""

    def __init__(
        self,
        *,
        player_count: int,
        resolve_tick_input: TickInputResolver | None = None,
        resolve_tick_commands: TickCommandResolver | None = None,
        emit_tick_command: TickCommandEmitter | None = None,
    ) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input
        self._resolve_tick_commands = resolve_tick_commands
        self._emit_tick_command = emit_tick_command
        self._pending_commands: list[GameCommand] = []
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
        if self._pending_commands:
            pending_commands = list(self._pending_commands)
            self._pending_commands.clear()
            emit_tick_command = self._emit_tick_command
            if emit_tick_command is not None:
                for command in pending_commands:
                    emit_tick_command(int(tick_index), command)
            commands.extend(pending_commands)
        resolve_commands = self._resolve_tick_commands
        if resolve_commands is not None:
            resolved_commands = resolve_commands(int(tick_index))
            if resolved_commands is not None:
                commands.extend(list(resolved_commands))
        if commands:
            self._queue_tick_commands(int(tick_index), commands)
        return TickInput(
            status=InputStatus.READY,
            inputs=normalize_provider_tick_inputs(inputs=inputs, player_count=self._player_count),
        )

    def supports_commands(self) -> bool:
        return True

    def push_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)

    def pull_tick_commands(self, tick_index: int) -> list[GameCommand]:
        return self._commands_by_tick.pop(int(tick_index), [])

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
        return default_dt

    def _queue_tick_commands(self, tick_index: int, commands: list[GameCommand]) -> None:
        self._commands_by_tick.setdefault(int(tick_index), []).extend(commands)
