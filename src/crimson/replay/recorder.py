from __future__ import annotations

from typing import Sequence

from ..sim.input import PlayerInput
from .input_codec import pack_tick_inputs
from .types import (
    PerkMenuOpenEvent,
    PerkPickEvent,
    PackedTickInputs,
    Replay,
    ReplayEvent,
    ReplayHeader,
    REPLAY_FORMAT_VERSION,
)


class ReplayRecorder:
    def __init__(self, header: ReplayHeader) -> None:
        if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
            raise ValueError(f"unsupported replay format version: {header.replay_format_version}")
        self._header = header
        self._tick_index = 0
        self._inputs: list[PackedTickInputs] = []
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

        tick = pack_tick_inputs(inputs, quant=self._header.input_quantization)

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
            header=self._header,
            inputs=self._inputs,
            events=list(self._events),
        )
