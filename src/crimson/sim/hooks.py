from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class LanFrameSample:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    commands: tuple[GameCommand, ...] = ()


@dataclass(frozen=True, slots=True)
class LanTickSync:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]


@dataclass(slots=True)
class LanSyncCallbacks:
    role: str
    take_frame_sample: Callable[[int], LanFrameSample | None]
    broadcast_tick_frame: Callable[[int, tuple[list[float], ...], tuple[GameCommand, ...]], None] | None = None
