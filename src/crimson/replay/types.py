from __future__ import annotations

import os
import platform
import sys

import msgspec

from ..game_version import current_replay_game_version
from ..math_parity import f32
from ..sim.commands import GameCommand
from ..sim.run_result import RunResult
from ..sim.run_spec import RunSpec

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


def current_platform() -> str:
    system = {"darwin": "macos", "win32": "windows"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    return f"{system}-{ {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(machine, machine) }"


def current_recorder() -> Recorder:
    return Recorder(client="crimson", version=current_replay_game_version(), platform=current_platform())


def current_pilot() -> Pilot | None:
    """The pilot a bot harness declares through `CRIMSON_PILOT_NAME`, `CRIMSON_PILOT_MODEL` and `CRIMSON_PILOT_URL`."""

    name = os.environ.get("CRIMSON_PILOT_NAME")
    if not name:
        return None
    return Pilot(name=name, model=os.environ.get("CRIMSON_PILOT_MODEL", ""), url=os.environ.get("CRIMSON_PILOT_URL", ""))


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


class Pilot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """The program that played a run, as its operator declares it (docs/rewrite/bots.md).

    Verification ignores it; a run that names one ranks on the bot boards.
    """

    # The bot's name, e.g. "Astra".
    name: str
    # The model or tool behind it, e.g. "gpt-5" or "TAS"; empty when not given.
    model: str = ""
    # An https:// page about it, such as the harness's repository; empty when not given.
    url: str = ""


class Replay(msgspec.Struct, forbid_unknown_fields=True):
    format_version: int
    # The build that recorded the run, which the ranked rules version boards by.
    game_version: str
    # The simulation rules the run plays under (REPLAY_RULES).
    rules: int
    recorder: Recorder
    # The program that played the run, when one did and says so (since v32).
    pilot: Pilot | None
    run: RunSpec
    result: RunResult
    ticks: list[ReplayTick]
