from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Literal, TypeAlias

import msgspec

from ..aim_schemes import AimScheme, aim_scheme_from_value
from ..game_modes import GameMode
from ..math_parity import f32
from ..movement_controls import MovementControlType, movement_control_type_from_value
from ..msgspec_types import NonNegativeInt, PlayerCount, PositiveFloat, PositiveInt
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..sim.input_providers import GameCommand
from ..weapon_usage import WEAPON_USAGE_SLOT_COUNT
from ..weapons import WeaponId

REPLAY_FORMAT_VERSION = 12

# v11 replays were recorded before run start modeled native `player_reset_all`
# (0x41fc80) weapon defaults; they play back with the legacy table-assigned
# pistol so existing recordings keep verifying.
LEGACY_REPLAY_FORMAT_VERSIONS = frozenset({11})
SUPPORTED_REPLAY_FORMAT_VERSIONS = frozenset({REPLAY_FORMAT_VERSION, *LEGACY_REPLAY_FORMAT_VERSIONS})

WEAPON_USAGE_COUNT = WEAPON_USAGE_SLOT_COUNT

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2
RELOAD_DOWN_FLAG = 1 << 16
MOVE_KEYS_PRESENT_FLAG = 1 << 3
MOVE_FORWARD_FLAG = 1 << 4
MOVE_BACKWARD_FLAG = 1 << 5
TURN_LEFT_FLAG = 1 << 6
TURN_RIGHT_FLAG = 1 << 7
MOVE_MODE_PRESENT_FLAG = 1 << 8
MOVE_MODE_SHIFT = 9
MOVE_MODE_MASK = 0x7
AIM_SCHEME_PRESENT_FLAG = 1 << 12
AIM_SCHEME_SHIFT = 13
AIM_SCHEME_MASK = 0x7

InputQuantization: TypeAlias = Literal["f32"]

_RELEASE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _head_points_at_release_tag(*, version: str, repo_root: Path, git_exe: str) -> bool:
    """Return True when HEAD is tagged as the release version."""

    if _RELEASE_VERSION_RE.fullmatch(str(version)) is None:
        return False

    tags_out = subprocess.check_output(
        [git_exe, "tag", "--points-at", "HEAD"],
        cwd=repo_root,
        stderr=subprocess.DEVNULL,
    )
    tags = {line.strip() for line in tags_out.decode("utf-8", errors="replace").splitlines() if line.strip()}
    return str(version) in tags or f"v{version}" in tags


@lru_cache(maxsize=1)
def current_replay_game_version() -> str:
    """Return replay header `game_version`.

    - Release-tagged HEAD: "<version>"
    - Git checkout non-release: "<version>+g<short_sha>"
    - No git metadata: "<version>"
    """

    from .. import __version__

    version = str(__version__)
    try:
        git_exe = shutil.which("git")
        if git_exe is None:
            return version
        repo_root = Path(__file__).resolve().parents[3]
        out = subprocess.check_output(
            [git_exe, "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
        build = out.decode("utf-8", errors="replace").strip()
        if not build:
            return version
        if _head_points_at_release_tag(version=version, repo_root=repo_root, git_exe=git_exe):
            return version
        if "+" in version:
            return f"{version}.g{build}"
        return f"{version}+g{build}"
    except (OSError, subprocess.CalledProcessError):
        return version


def _default_game_version() -> str:
    return current_replay_game_version()


def quantize_f32(value: float) -> float:
    return float(f32(float(value)))


def pack_input_flags(
    *,
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    reload_down: bool = False,
    move_mode: MovementControlType | None = None,
    aim_scheme: AimScheme | None = None,
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
    if reload_down:
        flags |= RELOAD_DOWN_FLAG
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
    if move_mode is not None:
        flags |= MOVE_MODE_PRESENT_FLAG
        flags |= (int(move_mode) & MOVE_MODE_MASK) << MOVE_MODE_SHIFT
    if aim_scheme is not None:
        flags |= AIM_SCHEME_PRESENT_FLAG
        flags |= (int(aim_scheme) & AIM_SCHEME_MASK) << AIM_SCHEME_SHIFT
    return int(flags)


def unpack_input_flags(flags: int) -> tuple[bool, bool, bool, bool]:
    flags = int(flags)
    return (
        bool(flags & FIRE_DOWN_FLAG),
        bool(flags & FIRE_PRESSED_FLAG),
        bool(flags & RELOAD_PRESSED_FLAG),
        bool(flags & RELOAD_DOWN_FLAG),
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


def unpack_input_mode_flags(flags: int) -> tuple[MovementControlType | None, AimScheme | None]:
    flags = int(flags)
    move_mode: MovementControlType | None = None
    aim_scheme: AimScheme | None = None
    if bool(flags & MOVE_MODE_PRESENT_FLAG):
        move_mode = movement_control_type_from_value((flags >> MOVE_MODE_SHIFT) & MOVE_MODE_MASK)
    if bool(flags & AIM_SCHEME_PRESENT_FLAG):
        aim_scheme_raw = (flags >> AIM_SCHEME_SHIFT) & AIM_SCHEME_MASK
        if aim_scheme_raw == AIM_SCHEME_MASK:
            aim_scheme_raw = -1
        aim_scheme = aim_scheme_from_value(aim_scheme_raw)
    return move_mode, aim_scheme


PackedPlayerInput: TypeAlias = list[float | int]
PackedTickInputs: TypeAlias = list[PackedPlayerInput]


def unpack_packed_player_input(packed: PackedPlayerInput) -> tuple[float, float, float, float, int]:
    """Decode a compact replay input row into scalar values.

    Stored shape is `[move_x, move_y, aim_x, aim_y, flags]`.
    Returns `(move_x, move_y, aim_x, aim_y, flags)`.
    """

    def _require_num_f(value: object, *, field: str) -> float:
        if isinstance(value, bool):
            raise TypeError(f"{field} must be numeric, got bool")
        if isinstance(value, (int, float)):
            return float(value)
        raise TypeError(f"{field} must be numeric")

    def _require_num_i(value: object, *, field: str) -> int:
        if isinstance(value, bool):
            raise TypeError(f"{field} must be numeric, got bool")
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            return int(value)
        raise TypeError(f"{field} must be numeric")

    if len(packed) != 5:
        raise ValueError(f"packed replay input must have 5 fields, got {len(packed)}")

    mx = _require_num_f(packed[0], field="move_x")
    my = _require_num_f(packed[1], field="move_y")
    ax = _require_num_f(packed[2], field="aim_x")
    ay = _require_num_f(packed[3], field="aim_y")
    flags = _require_num_i(packed[4], field="flags")

    return mx, my, ax, ay, flags


class ReplayClaimedStatsSnapshot(msgspec.Struct, frozen=True):
    complete: bool = False
    ticks: NonNegativeInt = 0
    elapsed_ms: NonNegativeInt = 0
    score_xp: NonNegativeInt = 0
    kills: NonNegativeInt = 0
    most_used_weapon_id: WeaponId = WeaponId.NONE
    shots_fired: NonNegativeInt = 0
    shots_hit: NonNegativeInt = 0


class ReplayHeader(msgspec.Struct, frozen=True):
    game_mode_id: GameMode
    seed: int
    replay_format_version: int = REPLAY_FORMAT_VERSION
    quest_level: QuestLevel | None = None
    typo_dictionary_words: tuple[str, ...] = ()
    typo_highscore_names: tuple[str, ...] = ()
    game_version: str = msgspec.field(default_factory=_default_game_version)
    tick_rate: PositiveInt = 60
    # Mirrors the native quest retry scaling counter (`quest_fail_retry_count`).
    quest_fail_retry_count: NonNegativeInt = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    detail_preset: NonNegativeInt = 5
    violence_disabled: NonNegativeInt = 0
    world_size: PositiveFloat = 1024.0
    player_count: PlayerCount = 1
    status: GameStatusData = msgspec.field(default_factory=GameStatusData)
    claimed_stats: ReplayClaimedStatsSnapshot = msgspec.field(default_factory=ReplayClaimedStatsSnapshot)
    input_quantization: InputQuantization = "f32"


class ReplayTick(msgspec.Struct, frozen=True):
    dt: float
    inputs: PackedTickInputs
    commands: list[GameCommand] = []


class Replay(msgspec.Struct):
    header: ReplayHeader
    ticks: list[ReplayTick]
