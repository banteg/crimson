from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import msgspec

if TYPE_CHECKING:
    from .input import PlayerInput

class TickHashes(msgspec.Struct, frozen=True):
    command_hash: str
    state_hash: str | None = None


class TickResult(msgspec.Struct):
    tick_index: int
    command_hash: str
    dt_sim: float
    presentation_plan_ms: float = 0.0
    payload: object | None = None
    inputs: list[PlayerInput] | None = None
    hashes: TickHashes | None = None
    replay_tick_index: int | None = None
    lan_sync: object | None = None


@dataclass(frozen=True, slots=True)
class LanFrameSample:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    remote_command_hash: str
    remote_state_hash: str


@dataclass(frozen=True, slots=True)
class LanTickSync:
    frame_tick_index: int
    frame_inputs: tuple[list[float], ...]
    remote_command_hash: str
    remote_state_hash: str
    host_state_hash: str = ""


@dataclass(slots=True)
class LanSyncCallbacks:
    role: str
    take_frame_sample: Callable[[int], LanFrameSample | None]
    state_hash_for_tick: Callable[[int, TickResult], str]
    should_emit_state_hash: Callable[[int], bool]
    note_desync: Callable[[str, int, str, str], None]
    broadcast_tick_frame: Callable[[int, tuple[list[float], ...], str, str], None] | None = None
