from __future__ import annotations

import math
from collections.abc import Sequence

from ..math_parity import f32
from ..sim.input import PlayerInput
from .input_codec import pack_tick_inputs
from .types import (
    REPLAY_FORMAT_VERSION,
    PackedTickInputs,
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    ReplayEvent,
    ReplayHeader,
)


class ReplayRecorder:
    def __init__(self, header: ReplayHeader) -> None:
        if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
            raise ValueError(f"unsupported replay format version: {header.replay_format_version}")
        self._header = header
        self._tick_index = 0
        self._inputs: list[PackedTickInputs] = []
        self._dt: list[float] = []
        self._events: list[ReplayEvent] = []  # TODO(PR-B): remove event side-channel, use record_tick(inputs, commands=...)

    @property
    def header(self) -> ReplayHeader:
        return self._header

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    @property
    def recorded_tick_count(self) -> int:
        return int(len(self._inputs))

    def _default_tick_dt(self) -> float:
        tick_rate = int(self._header.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"invalid tick_rate: {tick_rate}")
        return float(f32(1.0 / float(tick_rate)))

    def record_tick(self, inputs: Sequence[PlayerInput], *, dt: float | None = None) -> int:
        """Record a single simulation tick worth of inputs.

        Returns the tick index that was recorded.
        """

        player_count = int(self._header.player_count)
        if len(inputs) != player_count:
            raise ValueError(f"expected {player_count} player inputs, got {len(inputs)}")

        tick = pack_tick_inputs(inputs, quant=self._header.input_quantization)
        tick_dt = self._default_tick_dt() if dt is None else float(f32(float(dt)))
        if not math.isfinite(tick_dt) or tick_dt < 0.0:
            raise ValueError(f"dt must be finite and >= 0, got {tick_dt!r}")

        tick_index = int(self._tick_index)
        self._inputs.append(tick)
        self._dt.append(float(tick_dt))
        self._tick_index += 1
        return tick_index

    def record_tick_at(
        self,
        *,
        tick_index: int,
        inputs: Sequence[PlayerInput],
        allow_extend: bool = True,
        dt: float | None = None,
    ) -> int:
        """Record/overwrite inputs at an explicit tick index.

        When `tick_index` points to an existing entry, that entry is replaced.
        When it matches the current length and `allow_extend` is true, a new tick
        is appended.
        """

        target = int(tick_index)
        if target < 0:
            raise ValueError("tick_index must be >= 0")

        player_count = int(self._header.player_count)
        if len(inputs) != player_count:
            raise ValueError(f"expected {player_count} player inputs, got {len(inputs)}")

        tick = pack_tick_inputs(inputs, quant=self._header.input_quantization)
        tick_dt = self._default_tick_dt() if dt is None else float(f32(float(dt)))
        if not math.isfinite(tick_dt) or tick_dt < 0.0:
            raise ValueError(f"dt must be finite and >= 0, got {tick_dt!r}")
        length = len(self._inputs)

        if target < length:
            self._inputs[target] = tick
            self._dt[target] = float(tick_dt)
        elif target == length and bool(allow_extend):
            self._inputs.append(tick)
            self._dt.append(float(tick_dt))
        else:
            raise IndexError(f"tick_index {target} out of range for replay length {length}")

        self._tick_index = max(int(self._tick_index), target + 1)
        return int(target)

    def record_perk_pick(
        self,
        *,
        player_index: int,
        choice_index: int,
        tick_index: int | None = None,
    ) -> None:
        if tick_index is None:
            tick_index = int(self._tick_index)
        self._events.append(
            PerkPickEvent(
                tick_index=int(tick_index),
                player_index=int(player_index),
                choice_index=int(choice_index),
            ),
        )

    def record_perk_menu_open(
        self,
        *,
        player_index: int,
        tick_index: int | None = None,
    ) -> None:
        if tick_index is None:
            tick_index = int(self._tick_index)
        self._events.append(
            PerkMenuOpenEvent(
                tick_index=int(tick_index),
                player_index=int(player_index),
            ),
        )

    def finish(self) -> Replay:
        return Replay(
            header=self._header,
            inputs=self._inputs,
            dt=self._dt,
            events=list(self._events),
        )
