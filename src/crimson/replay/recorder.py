from __future__ import annotations

import math
from collections.abc import Sequence

from ..math_parity import f32
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

    def _default_tick_dt(self) -> float:
        tick_rate = int(self._header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        return float(f32(1.0 / float(tick_rate)))

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
        tick_dt: float | None = None
        if dt is not None:
            tick_dt = float(f32(float(dt)))
            if not math.isfinite(tick_dt) or tick_dt < 0.0:
                raise ValueError(f"dt must be finite and >= 0, got {tick_dt!r}")

        tick_index = int(self._tick_index)
        self._ticks.append(ReplayTick(inputs=packed, commands=list(commands) if commands else [], dt=tick_dt))
        self._tick_index += 1
        return tick_index

    def finish(self) -> Replay:
        return Replay(header=self._header, ticks=self._ticks)
