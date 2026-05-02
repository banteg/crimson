from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from .input_providers import ResolvedTick
from .sessions import DeterministicSessionTick

if TYPE_CHECKING:
    from .input_providers import GameCommand


class TickResult(msgspec.Struct):
    source_tick: ResolvedTick
    payload: DeterministicSessionTick
    replay_tick_index: int | None = None
    lan_sync: LanTickSync | None = None


class LanFrameSample(msgspec.Struct, frozen=True):
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    commands: tuple[GameCommand, ...] = ()


class LanTickSync(msgspec.Struct, frozen=True):
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
