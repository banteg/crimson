from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import msgspec

from .sessions import DeterministicSessionTick

if TYPE_CHECKING:
    from .input import PlayerInput
    from .input_providers import GameCommand

class TickResult(msgspec.Struct):
    tick_index: int
    payload: DeterministicSessionTick
    inputs: list[PlayerInput]
    commands: list[GameCommand]
    replay_tick_index: int | None = None
    lan_sync: LanTickSync | None = None


@dataclass(frozen=True, slots=True)
class LanFrameSample:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    remote_state_hash: str


@dataclass(frozen=True, slots=True)
class LanTickSync:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    remote_state_hash: str
    host_state_hash: str = ""


@dataclass(slots=True)
class LanSyncCallbacks:
    role: str
    take_frame_sample: Callable[[int], LanFrameSample | None]
    state_hash_for_tick: Callable[[int, TickResult], str]
    should_emit_state_hash: Callable[[int], bool]
    note_desync: Callable[[str, int, str, str], None]
    broadcast_tick_frame: Callable[[int, tuple[list[float], ...], str], None] | None = None
