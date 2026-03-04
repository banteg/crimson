from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

from ..sim.input import PlayerInput
from .input_codec import unpack_tick_inputs

if TYPE_CHECKING:
    from .types import Replay


class ReplayJournal:
    """Read-only replay journal adapter over persisted replay rows."""

    def __init__(
        self,
        *,
        replay: Replay,
        resolve_tick_dt: Callable[[int], float] | None = None,
    ) -> None:
        self._replay = replay
        self._resolve_tick_dt = resolve_tick_dt

    def tick_count(self) -> int:
        return int(len(self._replay.inputs))

    def read_tick_inputs(self, tick_index: int) -> Sequence[PlayerInput] | None:
        idx = int(tick_index)
        if idx < 0:
            return None
        if idx >= len(self._replay.inputs):
            return None
        return unpack_tick_inputs(self._replay.inputs[idx])

    def read_tick_dt(self, tick_index: int, default_dt: float) -> float:
        resolver = self._resolve_tick_dt
        if resolver is None:
            return float(default_dt)
        return float(resolver(int(tick_index)))
