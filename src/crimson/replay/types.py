from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

ReplayFormatVersion: TypeAlias = Literal[1]

WEAPON_USAGE_COUNT = 53

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2
MOVE_KEYS_PRESENT_FLAG = 1 << 3
MOVE_FORWARD_FLAG = 1 << 4
MOVE_BACKWARD_FLAG = 1 << 5
TURN_LEFT_FLAG = 1 << 6
TURN_RIGHT_FLAG = 1 << 7

InputQuantization: TypeAlias = Literal["raw", "f32"]


def _default_game_version() -> str:
    from .. import __version__

    return str(__version__)


def pack_input_flags(
    *,
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    move_forward_pressed: bool | None = None,
    move_backward_pressed: bool | None = None,
    turn_left_pressed: bool | None = None,
    turn_right_pressed: bool | None = None,
) -> int:
    flags = 0
    if fire_down:
        flags |= FIRE_DOWN_FLAG
    if fire_pressed:
        flags |= FIRE_PRESSED_FLAG
    if reload_pressed:
        flags |= RELOAD_PRESSED_FLAG
    key_fields = (
        move_forward_pressed,
        move_backward_pressed,
        turn_left_pressed,
        turn_right_pressed,
    )
    if any(field is not None for field in key_fields):
        flags |= MOVE_KEYS_PRESENT_FLAG
        if bool(move_forward_pressed):
            flags |= MOVE_FORWARD_FLAG
        if bool(move_backward_pressed):
            flags |= MOVE_BACKWARD_FLAG
        if bool(turn_left_pressed):
            flags |= TURN_LEFT_FLAG
        if bool(turn_right_pressed):
            flags |= TURN_RIGHT_FLAG
    return int(flags)


def unpack_input_flags(flags: int) -> tuple[bool, bool, bool]:
    flags = int(flags)
    return (
        bool(flags & FIRE_DOWN_FLAG),
        bool(flags & FIRE_PRESSED_FLAG),
        bool(flags & RELOAD_PRESSED_FLAG),
    )


def unpack_input_move_key_flags(flags: int) -> tuple[bool | None, bool | None, bool | None, bool | None]:
    flags = int(flags)
    if not bool(flags & MOVE_KEYS_PRESENT_FLAG):
        return None, None, None, None
    return (
        bool(flags & MOVE_FORWARD_FLAG),
        bool(flags & MOVE_BACKWARD_FLAG),
        bool(flags & TURN_LEFT_FLAG),
        bool(flags & TURN_RIGHT_FLAG),
    )


PackedPlayerInput: TypeAlias = list[float | int | list[float]]
PackedTickInputs: TypeAlias = list[PackedPlayerInput]


def unpack_packed_player_input(packed: PackedPlayerInput) -> tuple[float, float, float, float, int]:
    """Decode a compact replay input row into scalar values.

    Stored shape is `[move_x, move_y, [aim_x, aim_y], flags]`.
    Returns `(move_x, move_y, aim_x, aim_y, flags)` with tolerant numeric coercion.
    """

    def _num_f(value: object) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        return 0.0

    def _num_i(value: object) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            return int(value)
        return 0

    if len(packed) < 4:
        return 0.0, 0.0, 0.0, 0.0, 0

    mx = _num_f(packed[0])
    my = _num_f(packed[1])
    flags = _num_i(packed[3])

    aim_raw = packed[2]
    if isinstance(aim_raw, list) and len(aim_raw) >= 2:
        ax = _num_f(aim_raw[0])
        ay = _num_f(aim_raw[1])
    else:
        ax = 0.0
        ay = 0.0

    return mx, my, ax, ay, flags


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
