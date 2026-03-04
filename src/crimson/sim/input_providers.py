from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, TypeAlias

import msgspec

from ..local_input import clear_input_edges
from .input import PlayerInput
from .input_frame import normalize_input_frame


class ReplayEndOfStream(RuntimeError):
    """Raised when replay input requests pass the last recorded tick."""


class InputCommand(msgspec.Struct, frozen=True):
    name: str
    payload: dict[str, object] = msgspec.field(default_factory=dict)


class FrameContext(msgspec.Struct, frozen=True):
    dt_seconds: float
    tick_dt_seconds: float
    frame_index: int
    candidate_ticks: int
    is_networked: bool = False
    is_replay: bool = False


class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None: ...

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]: ...

    def push_command(self, command: InputCommand) -> None: ...


TickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickDtResolver: TypeAlias = Callable[[int], float]
TickCommandResolver: TypeAlias = Callable[[int], Sequence[InputCommand] | None]
LocalInputBuilder: TypeAlias = Callable[[FrameContext], Sequence[PlayerInput]]


def normalize_provider_tick_inputs(*, inputs: Sequence[PlayerInput], player_count: int) -> list[PlayerInput]:
    """Normalize provider output to a fixed player-index order."""

    count = max(0, player_count)
    if count > 0 and len(inputs) == 0:
        raise ValueError("empty input list is invalid when player_count > 0")
    return normalize_input_frame(inputs, player_count=count).as_list()


class LocalInputProvider:
    """Adapter over local input polling; never returns stall (`None`)."""

    def __init__(
        self,
        *,
        player_count: int,
        build_inputs: LocalInputBuilder,
    ) -> None:
        self._player_count = max(0, player_count)
        self._build_inputs = build_inputs
        self._pending_commands: list[InputCommand] = []
        self._commands_for_next_tick: list[InputCommand] = []
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

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        if self._player_count <= 0:
            return []
        if self._first_tick_pending:
            self._first_tick_pending = False
            return list(self._frame_inputs)
        return list(self._edge_inputs)

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        _ = tick_index
        if not self._commands_for_next_tick:
            return []
        commands = list(self._commands_for_next_tick)
        self._commands_for_next_tick.clear()
        return commands

    def push_command(self, command: InputCommand) -> None:
        self._pending_commands.append(command)


class ReplayInputProvider:
    """Deterministic adapter over recorded replay input rows."""

    def __init__(
        self,
        *,
        player_count: int,
        resolve_tick_input: ReplayTickInputResolver,
        tick_count: int | None = None,
        resolve_tick_dt: ReplayTickDtResolver | None = None,
    ) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input
        self._resolve_tick_dt = resolve_tick_dt
        if tick_count is not None:
            self._tick_count = max(0, tick_count)
        else:
            self._tick_count = None

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        idx = tick_index
        if idx < 0:
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        tick_count = self._tick_count
        if tick_count is not None and idx >= tick_count:
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        resolved = self._resolve_tick_input(idx)
        if resolved is None:
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        row = list(resolved)
        return normalize_provider_tick_inputs(inputs=row, player_count=self._player_count)

    def push_command(self, command: InputCommand) -> None:
        raise RuntimeError(f"replay input provider does not accept commands: {command.name}")

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        _ = tick_index
        return []

    def resolve_tick_dt(self, tick_index: int, default_dt: float) -> float:
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
    ) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input
        self._resolve_tick_commands = resolve_tick_commands
        self._pending_commands: list[InputCommand] = []
        self._commands_by_tick: dict[int, list[InputCommand]] = {}

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        resolver = self._resolve_tick_input
        if resolver is None:
            return None
        inputs = resolver(tick_index)
        if inputs is None:
            return None
        commands: list[InputCommand] = []
        if self._pending_commands:
            commands.extend(self._pending_commands)
            self._pending_commands.clear()
        resolve_commands = self._resolve_tick_commands
        if resolve_commands is not None:
            resolved_commands = resolve_commands(int(tick_index))
            if resolved_commands is not None:
                commands.extend(list(resolved_commands))
        if commands:
            self._queue_tick_commands(int(tick_index), commands)
        return normalize_provider_tick_inputs(inputs=inputs, player_count=self._player_count)

    def push_command(self, command: InputCommand) -> None:
        self._pending_commands.append(command)

    def pull_tick_commands(self, tick_index: int) -> list[InputCommand]:
        return self._commands_by_tick.pop(int(tick_index), [])

    def _queue_tick_commands(self, tick_index: int, commands: list[InputCommand]) -> None:
        self._commands_by_tick.setdefault(int(tick_index), []).extend(commands)
