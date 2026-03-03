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


class InputProvider(Protocol):
    def begin_frame(self) -> None: ...

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None: ...


TickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
ReplayTickInputResolver: TypeAlias = Callable[[int], Sequence[PlayerInput] | None]
LocalInputBuilder: TypeAlias = Callable[[], Sequence[PlayerInput]]


def normalize_provider_tick_inputs(*, inputs: Sequence[PlayerInput], player_count: int) -> list[PlayerInput]:
    """Normalize provider output to a fixed player-index order."""

    count = max(0, int(player_count))
    if count > 0 and len(inputs) == 0:
        raise ValueError("empty input list is invalid when player_count > 0")
    return normalize_input_frame(inputs, player_count=count).as_list()


class LocalInputProvider:
    """Adapter over local input polling; never returns stall (`None`)."""

    def __init__(self, *, player_count: int, build_inputs: LocalInputBuilder) -> None:
        self._player_count = max(0, int(player_count))
        self._build_inputs = build_inputs
        self._frame_inputs: list[PlayerInput] = []
        self._edge_inputs: list[PlayerInput] = []
        self._first_tick_pending = False

    def begin_frame(self) -> None:
        frame_inputs = list(self._build_inputs())
        self._frame_inputs = normalize_provider_tick_inputs(inputs=frame_inputs, player_count=self._player_count)
        self._edge_inputs = clear_input_edges(self._frame_inputs)
        self._first_tick_pending = True

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        _ = tick_index
        if self._player_count <= 0:
            return []
        if self._first_tick_pending:
            self._first_tick_pending = False
            return list(self._frame_inputs)
        return list(self._edge_inputs)


class ReplayInputProvider:
    """Deterministic adapter over recorded replay input rows."""

    def __init__(
        self,
        *,
        player_count: int,
        resolve_tick_input: ReplayTickInputResolver,
        tick_count: int | None = None,
    ) -> None:
        self._player_count = max(0, int(player_count))
        self._resolve_tick_input = resolve_tick_input
        if tick_count is not None:
            self._tick_count = max(0, int(tick_count))
        else:
            self._tick_count = None

    def begin_frame(self) -> None:
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        idx = int(tick_index)
        if idx < 0:
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        tick_count = self._tick_count
        if tick_count is not None and idx >= int(tick_count):
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        resolved = self._resolve_tick_input(int(idx))
        if resolved is None:
            raise ReplayEndOfStream(f"replay input exhausted at tick {idx}")
        row = list(resolved)
        return normalize_provider_tick_inputs(inputs=row, player_count=self._player_count)


class NetworkInputProvider:
    """Runtime-backed input source; may stall when a tick is not ready yet."""

    def __init__(self, *, player_count: int, resolve_tick_input: TickInputResolver | None = None) -> None:
        self._player_count = max(0, int(player_count))
        self._resolve_tick_input = resolve_tick_input

    def begin_frame(self) -> None:
        return

    def pull_tick_input(self, tick_index: int) -> list[PlayerInput] | None:
        resolver = self._resolve_tick_input
        if resolver is None:
            return None
        inputs = resolver(int(tick_index))
        if inputs is None:
            return None
        return normalize_provider_tick_inputs(inputs=inputs, player_count=self._player_count)
