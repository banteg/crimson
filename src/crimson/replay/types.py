from __future__ import annotations

import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import msgspec

from ..aim_schemes import AimScheme, aim_scheme_from_value
from ..math_parity import f32
from ..movement_controls import MovementControlType, movement_control_type_from_value
from ..sim.input_providers import GameCommand
from ..sim.run_result import RunResult
from ..sim.run_spec import RunSpec

REPLAY_FORMAT_VERSION = 20
# Replays step a fixed 60 Hz schedule; every tick uses this float32 delta.
REPLAY_TICK_RATE = 60
REPLAY_TICK_DT = float(f32(1.0 / REPLAY_TICK_RATE))

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2
RELOAD_DOWN_FLAG = 1 << 16
FIRE_BULLETS_KEY_DOWN_FLAG = 1 << 17
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

SUPPORTED_INPUT_FLAGS_MASK = (
    FIRE_DOWN_FLAG
    | FIRE_PRESSED_FLAG
    | RELOAD_PRESSED_FLAG
    | RELOAD_DOWN_FLAG
    | FIRE_BULLETS_KEY_DOWN_FLAG
    | MOVE_KEYS_PRESENT_FLAG
    | MOVE_FORWARD_FLAG
    | MOVE_BACKWARD_FLAG
    | TURN_LEFT_FLAG
    | TURN_RIGHT_FLAG
    | MOVE_MODE_PRESENT_FLAG
    | (MOVE_MODE_MASK << MOVE_MODE_SHIFT)
    | AIM_SCHEME_PRESENT_FLAG
    | (AIM_SCHEME_MASK << AIM_SCHEME_SHIFT)
)


def input_flags_validation_error(flags: int) -> str | None:
    value = int(flags)
    if value < 0 or value > 0xFFFFFFFF or value & ~SUPPORTED_INPUT_FLAGS_MASK:
        return "contain unsupported bits"
    move_key_bits = MOVE_FORWARD_FLAG | MOVE_BACKWARD_FLAG | TURN_LEFT_FLAG | TURN_RIGHT_FLAG
    if not value & MOVE_KEYS_PRESENT_FLAG and value & move_key_bits:
        return "set movement-key values without MOVE_KEYS_PRESENT"
    move_mode_value = (value >> MOVE_MODE_SHIFT) & MOVE_MODE_MASK
    if not value & MOVE_MODE_PRESENT_FLAG and move_mode_value != 0:
        return "set a movement mode without MOVE_MODE_PRESENT"
    if value & MOVE_MODE_PRESENT_FLAG and move_mode_value > 5:
        return "contain an invalid movement mode"
    aim_scheme_value = (value >> AIM_SCHEME_SHIFT) & AIM_SCHEME_MASK
    if not value & AIM_SCHEME_PRESENT_FLAG and aim_scheme_value != 0:
        return "set an aim scheme without AIM_SCHEME_PRESENT"
    if value & AIM_SCHEME_PRESENT_FLAG and aim_scheme_value not in {0, 1, 2, 3, 4, 5, 7}:
        return "contain an invalid aim scheme"
    return None


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


def _tree_is_dirty(*, repo_root: Path, git_exe: str) -> bool:
    """Return True when game sources differ from HEAD, including new unignored files."""

    out = subprocess.check_output(
        [git_exe, "status", "--porcelain", "--", "src"],
        cwd=repo_root,
        stderr=subprocess.DEVNULL,
    )
    return bool(out.strip())


@lru_cache(maxsize=1)
def current_replay_game_version() -> str:
    """Return replay `game_version`.

    - Release-tagged HEAD: "<version>"
    - Git checkout non-release: "<version>+g<short_sha>"
    - Modified game sources append ".dirty": the commit alone no longer
      identifies the simulation that recorded the replay.
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
        dirty = _tree_is_dirty(repo_root=repo_root, git_exe=git_exe)
        if not dirty and _head_points_at_release_tag(version=version, repo_root=repo_root, git_exe=git_exe):
            return version
        separator = "." if "+" in version else "+"
        return f"{version}{separator}g{build}" + (".dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return version


def quantize_f32(value: float) -> float:
    return float(f32(float(value)))


def pack_input_flags(
    *,
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    reload_down: bool = False,
    fire_bullets_key_down: bool = False,
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
    if fire_bullets_key_down:
        flags |= FIRE_BULLETS_KEY_DOWN_FLAG
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


# `(move_x, move_y, aim_x, aim_y, flags)`; axes are canonical float32 values.
type PackedPlayerInput = tuple[float, float, float, float, int]
type PackedTickInputs = list[PackedPlayerInput]


class ReplayTick(msgspec.Struct, frozen=True, array_like=True, forbid_unknown_fields=True):
    """One fixed-dt simulation tick: per-player inputs, then ordered commands.

    Perk commands apply at the start of the tick, before timing is derived;
    Typ-o commands apply after the mode's pre-step hook.
    """

    inputs: PackedTickInputs
    commands: list[GameCommand] = []


class Replay(msgspec.Struct, forbid_unknown_fields=True):
    format_version: int
    game_version: str
    run: RunSpec
    result: RunResult
    ticks: list[ReplayTick]
