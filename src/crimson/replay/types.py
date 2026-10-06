from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import msgspec

from ..math_parity import f32
from ..sim.commands import GameCommand
from ..sim.run_result import RunResult
from ..sim.run_spec import RunSpec

REPLAY_FORMAT_VERSION = 30
# Replays step a fixed 60 Hz schedule; every tick uses this float32 delta.
REPLAY_TICK_RATE = 60
REPLAY_TICK_DT = f32(1.0 / REPLAY_TICK_RATE)

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2
RELOAD_DOWN_FLAG = 1 << 16
FIRE_BULLETS_KEY_DOWN_FLAG = 1 << 17
# Held aim-turn controls: the aim keys under keyboard aim, the POV hat under joystick aim.
AIM_TURN_LEFT_FLAG = 1 << 18
AIM_TURN_RIGHT_FLAG = 1 << 19
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
    | AIM_TURN_LEFT_FLAG
    | AIM_TURN_RIGHT_FLAG
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


def current_platform() -> str:
    system = {"darwin": "macos", "win32": "windows"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    return f"{system}-{ {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(machine, machine) }"


def current_recorder() -> Recorder:
    return Recorder(client="crimson", version=current_replay_game_version(), platform=current_platform())


@lru_cache(maxsize=1)
def current_replay_game_version() -> str:
    """Return replay `game_version`.

    - Release-tagged HEAD: "<version>"
    - Git checkout non-release: "<version>+g<short_sha>"
    - Modified game sources append ".dirty": the commit alone no longer
      identifies the simulation that recorded the replay.
    - No git metadata or an installed package: "<version>"
    """

    from .. import __version__

    version = str(__version__)
    try:
        git_exe = shutil.which("git")
        if git_exe is None:
            return version
        repo_root = Path(__file__).resolve().parents[3]
        if not (repo_root / "pyproject.toml").is_file():
            # An installed package: parents[3] is the environment's lib dir, which may sit in an unrelated repo.
            return version
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


# `(move_x, move_y, aim_x, aim_y, flags)`; axes are canonical float32 values.
type PackedPlayerInput = tuple[float, float, float, float, int]
type PackedTickInputs = list[PackedPlayerInput]


class ReplayTick(msgspec.Struct, frozen=True, array_like=True, forbid_unknown_fields=True):
    """One fixed-dt simulation tick: per-player inputs, then ordered commands.

    Perk picks apply at the start of the tick, before timing is derived; a perk
    menu request opens mid-tick, where native opens it; Typ-o commands apply at the
    start of the Typ-o frame.
    """

    inputs: PackedTickInputs
    commands: list[GameCommand] = []


class Recorder(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """The program that recorded a replay. Verification ignores it; boards can show, filter or withdraw by it."""

    # "crimson" for this port; another client, such as a native crimson-core build, names itself.
    client: str
    # The client's own build, in `game_version`'s form.
    version: str
    # "<os>-<cpu>", e.g. "macos-arm64".
    platform: str


class Replay(msgspec.Struct, forbid_unknown_fields=True):
    format_version: int
    # The rules the run was recorded under: the build of the simulation and ranked rules it follows.
    game_version: str
    recorder: Recorder
    run: RunSpec
    result: RunResult
    ticks: list[ReplayTick]
