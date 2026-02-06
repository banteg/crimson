from __future__ import annotations

import struct
from typing import Sequence

from ..gameplay import PlayerInput
from .types import PerkMenuOpenEvent, PerkPickEvent, Replay, ReplayEvent, ReplayHeader, pack_input_flags

_FORMAT_VERSION = 1


def _quantize_f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


class ReplayRecorder:
    def __init__(self, header: ReplayHeader, *, version: int = _FORMAT_VERSION) -> None:
        if int(version) != _FORMAT_VERSION:
            raise ValueError(f"unsupported replay version: {version}")
        self._version = int(version)
        self._header = header
        self._tick_index = 0
        self._inputs: list[list[list[float | int]]] = []
        self._events: list[ReplayEvent] = []

    @property
    def header(self) -> ReplayHeader:
        return self._header

    @property
    def tick_index(self) -> int:
        return int(self._tick_index)

    def record_tick(self, inputs: Sequence[PlayerInput]) -> int:
        """Record a single simulation tick worth of inputs.

        Returns the tick index that was recorded.
        """

        player_count = int(self._header.player_count)
        if len(inputs) != player_count:
            raise ValueError(f"expected {player_count} player inputs, got {len(inputs)}")

        quant = self._header.input_quantization
        tick: list[list[float | int]] = []
        for inp in inputs:
            mx = float(inp.move_x)
            my = float(inp.move_y)
            ax = float(inp.aim.x)
            ay = float(inp.aim.y)
            if quant == "f32":
                mx = _quantize_f32(mx)
                my = _quantize_f32(my)
                ax = _quantize_f32(ax)
                ay = _quantize_f32(ay)
            flags = pack_input_flags(
                fire_down=bool(inp.fire_down),
                fire_pressed=bool(inp.fire_pressed),
                reload_pressed=bool(inp.reload_pressed),
            )
            tick.append([mx, my, [ax, ay], flags])

        tick_index = int(self._tick_index)
        self._inputs.append(tick)
        self._tick_index += 1
        return tick_index

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
            )
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
            )
        )

    def finish(self) -> Replay:
        return Replay(
            version=int(self._version),
            header=self._header,
            inputs=self._inputs,
            events=list(self._events),
        )
