from __future__ import annotations

import math
from collections.abc import Sequence

from ..sim.input import PlayerInput
from ..sim.input_providers import GameCommand
from .input_codec import pack_tick_inputs
from .types import (
    REPLAY_FORMAT_VERSION,
    Replay,
    ReplayHeader,
    ReplayTick,
)


class ReplayRecorder:
    def __init__(self, header: ReplayHeader) -> None:
        if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
            raise ValueError(f"unsupported replay format version: {header.replay_format_version}")
        self._header = header
        self._tick_index = 0
        self._ticks: list[ReplayTick] = []

    @property
    def header(self) -> ReplayHeader:
        return self._header

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    @property
    def recorded_tick_count(self) -> int:
        return len(self._ticks)

    def record_tick(
        self,
        inputs: Sequence[PlayerInput],
        *,
        commands: list[GameCommand] | None = None,
        dt: float | None = None,
    ) -> int:
        """Record a single simulation tick worth of inputs.

        Returns the tick index that was recorded.
        """

        player_count = int(self._header.player_count)
        if len(inputs) != player_count:
            raise ValueError(f"expected {player_count} player inputs, got {len(inputs)}")

        packed = pack_tick_inputs(inputs, quant=self._header.input_quantization)
        if dt is not None and (not math.isfinite(dt) or dt < 0.0):
            raise ValueError(f"dt must be finite and >= 0, got {dt!r}")

        tick_index = int(self._tick_index)
        self._ticks.append(ReplayTick(inputs=packed, commands=list(commands) if commands else [], dt=dt))
        self._tick_index += 1
        return tick_index

    def finish(self) -> Replay:
        return Replay(header=self._header, ticks=self._ticks)
