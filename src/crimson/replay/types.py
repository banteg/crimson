from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

ReplayFormatVersion: TypeAlias = Literal[1]

WEAPON_USAGE_COUNT = 53

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2

InputQuantization: TypeAlias = Literal["raw", "f32"]


def _default_game_version() -> str:
    from .. import __version__

    return str(__version__)


def pack_input_flags(*, fire_down: bool, fire_pressed: bool, reload_pressed: bool) -> int:
    flags = 0
    if fire_down:
        flags |= FIRE_DOWN_FLAG
    if fire_pressed:
        flags |= FIRE_PRESSED_FLAG
    if reload_pressed:
        flags |= RELOAD_PRESSED_FLAG
    return int(flags)


def unpack_input_flags(flags: int) -> tuple[bool, bool, bool]:
    flags = int(flags)
    return (
        bool(flags & FIRE_DOWN_FLAG),
        bool(flags & FIRE_PRESSED_FLAG),
        bool(flags & RELOAD_PRESSED_FLAG),
    )


PackedPlayerInput: TypeAlias = list[float | int | list[float]]
PackedTickInputs: TypeAlias = list[PackedPlayerInput]


@dataclass(frozen=True, slots=True)
class ReplayStatusSnapshot:
    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: tuple[int, ...] = field(default_factory=lambda: (0,) * WEAPON_USAGE_COUNT)


@dataclass(frozen=True, slots=True)
class ReplayHeader:
    game_mode_id: int
    seed: int
    game_version: str = field(default_factory=_default_game_version)
    tick_rate: int = 60
    difficulty_level: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    world_size: float = 1024.0
    player_count: int = 1
    status: ReplayStatusSnapshot = field(default_factory=ReplayStatusSnapshot)
    input_quantization: InputQuantization = "raw"


@dataclass(frozen=True, slots=True)
class PerkPickEvent:
    tick_index: int
    player_index: int
    choice_index: int


@dataclass(frozen=True, slots=True)
class PerkMenuOpenEvent:
    tick_index: int
    player_index: int


@dataclass(frozen=True, slots=True)
class UnknownEvent:
    tick_index: int
    kind: str
    payload: list[object]


ReplayEvent: TypeAlias = PerkPickEvent | PerkMenuOpenEvent | UnknownEvent


@dataclass(slots=True)
class Replay:
    version: int
    header: ReplayHeader
    inputs: list[PackedTickInputs]
    events: list[ReplayEvent] = field(default_factory=list)
