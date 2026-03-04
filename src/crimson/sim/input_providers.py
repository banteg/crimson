from __future__ import annotations

import inspect
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
    session_kind: str = "gameplay"
    mode_id: str = ""


class InputProvider(Protocol):
    def begin_frame(self, frame_ctx: FrameContext) -> None: ...

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None: ...

    def push_command(self, command: InputCommand) -> None: ...


TickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
LocalInputBuilder: TypeAlias = Callable[..., Sequence[PlayerInput]]


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
        command_consumer: Callable[[InputCommand, float], None] | None = None,
    ) -> None:
        self._player_count = max(0, player_count)
        self._build_inputs = build_inputs
        try:
            self._build_inputs_accepts_context = len(inspect.signature(build_inputs).parameters) > 0
        except (TypeError, ValueError):
            self._build_inputs_accepts_context = False
        self._command_consumer = command_consumer
        self._pending_commands: list[InputCommand] = []
        self._frame_inputs: list[PlayerInput] = []
        self._edge_inputs: list[PlayerInput] = []
        self._first_tick_pending = False

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        if self._build_inputs_accepts_context:
            frame_inputs = list(self._build_inputs(frame_ctx))
        else:
            frame_inputs = list(self._build_inputs())
        self._frame_inputs = normalize_provider_tick_inputs(inputs=frame_inputs, player_count=self._player_count)
        self._edge_inputs = clear_input_edges(self._frame_inputs)
        self._first_tick_pending = True
        command_consumer = self._command_consumer
        if command_consumer is not None:
            dt_tick = float(frame_ctx.tick_dt_seconds)
            for command in self._pending_commands:
                command_consumer(command, float(dt_tick))
        self._pending_commands.clear()

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        if self._player_count <= 0:
            return []
        if self._first_tick_pending:
            self._first_tick_pending = False
            return list(self._frame_inputs)
        return list(self._edge_inputs)

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
    ) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input
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


class NetworkInputProvider:
    """Runtime-backed input source; may stall when a tick is not ready yet."""

    def __init__(self, *, player_count: int, resolve_tick_input: TickInputResolver | None = None) -> None:
        self._player_count = max(0, player_count)
        self._resolve_tick_input = resolve_tick_input

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
        return normalize_provider_tick_inputs(inputs=inputs, player_count=self._player_count)

    def push_command(self, command: InputCommand) -> None:
        _ = command
