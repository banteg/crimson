"""Modern controller profile, applied when a player first uses a pad.

The stock `crimson.cfg` bindings are the original's DirectInput-era defaults
(swapped `JoyAxis*` aim axes, `JoyAxisZ`/`JoyRotX` movement), which put a modern
controller's movement on the wrong stick.  When a player touches their pad, every
binding that still holds its stock value and matters for pad play moves to the
standard controller codes, and the config is saved:

- a fully stock player also switches aim and movement to Dual Action Pad, so they
  get the whole twin-stick profile;
- stock axis pairs become the sticks (only pad methods read them);
- with pad aim, a stock Fire becomes R2;
- for player 1 on any pad method, stock Reload and Level Up become pad buttons.

Methods and bindings the player changed are never touched.  Each upgrade replaces
a stock value, so after one pass nothing is pending and it never re-triggers.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Flag, auto

import msgspec

from grim.config import (
    DEFAULT_PICK_PERK_CODE,
    DEFAULT_RELOAD_CODE,
    CrimsonControlsConfig,
    default_player_controls,
)

from .aim_schemes import AimScheme
from .input_codes import PadCode, gamepad_has_activity, player_gamepad_index
from .movement_controls import MovementControlType

PAD_PROFILE_MOVE_AXIS_CODES = (int(PadCode.LEFT_STICK_Y), int(PadCode.LEFT_STICK_X))
PAD_PROFILE_AIM_AXIS_CODES = (int(PadCode.RIGHT_STICK_Y), int(PadCode.RIGHT_STICK_X))
PAD_PROFILE_FIRE_CODE = int(PadCode.R2)
PAD_PROFILE_RELOAD_CODE = int(PadCode.FACE_LEFT)
PAD_PROFILE_PICK_PERK_CODE = int(PadCode.FACE_UP)


class PadUpgrade(Flag):
    METHODS = auto()
    MOVE_AXES = auto()
    AIM_AXES = auto()
    FIRE = auto()
    RELOAD = auto()
    LEVEL_UP = auto()

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(_PAD_UPGRADE_LABELS[member] for member in self)


_PAD_UPGRADE_LABELS: dict[PadUpgrade, str] = {
    PadUpgrade.METHODS: "aim/move methods",
    PadUpgrade.MOVE_AXES: "move axes",
    PadUpgrade.AIM_AXES: "aim axes",
    PadUpgrade.FIRE: "fire",
    PadUpgrade.RELOAD: "reload",
    PadUpgrade.LEVEL_UP: "level up",
}


class PlayerPadUpgrade(msgspec.Struct, frozen=True):
    player_index: int
    upgrades: PadUpgrade


def player_bindings_are_stock(controls: CrimsonControlsConfig, player_index: int) -> bool:
    stock = default_player_controls(player_index)
    player = controls.player(player_index)
    # The direction-arrow toggle is a HUD preference, not a binding.
    return msgspec.structs.replace(player, show_direction_arrow=stock.show_direction_arrow) == stock


def pending_pad_upgrades(controls: CrimsonControlsConfig, player_index: int) -> PadUpgrade:
    """Upgrades the next pad use would apply to this player (see module docstring)."""

    idx = int(player_index)
    stock = default_player_controls(idx)
    player = controls.player(idx)
    upgrades = PadUpgrade(0)
    if player_bindings_are_stock(controls, idx):
        upgrades |= PadUpgrade.METHODS
    switching = PadUpgrade.METHODS in upgrades
    aim_pad = switching or player.aim_scheme is AimScheme.DUAL_ACTION_PAD
    any_pad = aim_pad or player.movement is MovementControlType.DUAL_ACTION_PAD
    if player.move_axis_codes == stock.move_axis_codes:
        upgrades |= PadUpgrade.MOVE_AXES
    if player.aim_axis_codes == stock.aim_axis_codes:
        upgrades |= PadUpgrade.AIM_AXES
    if aim_pad and player.fire_code == stock.fire_code:
        upgrades |= PadUpgrade.FIRE
    # Reload and Level Up are global codes owned by player 1 (Controls edits them there).
    if idx == 0 and any_pad:
        if controls.reload_code == DEFAULT_RELOAD_CODE:
            upgrades |= PadUpgrade.RELOAD
        if controls.pick_perk_code == DEFAULT_PICK_PERK_CODE:
            upgrades |= PadUpgrade.LEVEL_UP
    return upgrades


def apply_pad_upgrades(controls: CrimsonControlsConfig, player_index: int, upgrades: PadUpgrade) -> None:
    """Apply upgrades; keyboard codes stay, so keyboard methods keep their stock keys."""

    player = controls.player(player_index)
    if PadUpgrade.METHODS in upgrades:
        player.movement = MovementControlType.DUAL_ACTION_PAD
        player.aim_scheme = AimScheme.DUAL_ACTION_PAD
    if PadUpgrade.MOVE_AXES in upgrades:
        player.move_axis_codes = PAD_PROFILE_MOVE_AXIS_CODES
    if PadUpgrade.AIM_AXES in upgrades:
        player.aim_axis_codes = PAD_PROFILE_AIM_AXIS_CODES
    if PadUpgrade.FIRE in upgrades:
        player.fire_code = PAD_PROFILE_FIRE_CODE
    if PadUpgrade.RELOAD in upgrades:
        controls.reload_code = PAD_PROFILE_RELOAD_CODE
    if PadUpgrade.LEVEL_UP in upgrades:
        controls.pick_perk_code = PAD_PROFILE_PICK_PERK_CODE


def apply_pad_profile(controls: CrimsonControlsConfig, player_index: int) -> None:
    """Switch a stock player to the full twin-stick profile."""

    apply_pad_upgrades(controls, player_index, pending_pad_upgrades(controls, player_index))


def auto_apply_pad_profiles(
    controls: CrimsonControlsConfig,
    *,
    player_count: int,
    pad_active: Callable[[int], bool] = gamepad_has_activity,
) -> tuple[PlayerPadUpgrade, ...]:
    """Apply pending upgrades for each active player whose pad is in use.

    Returns what changed per player; the caller logs it and persists the config.
    """

    applied: list[PlayerPadUpgrade] = []
    for player_index in range(max(1, min(len(controls.players), int(player_count)))):
        upgrades = pending_pad_upgrades(controls, player_index)
        if not upgrades:
            continue
        if not pad_active(player_gamepad_index(player_index)):
            continue
        apply_pad_upgrades(controls, player_index, upgrades)
        applied.append(PlayerPadUpgrade(player_index=player_index, upgrades=upgrades))
    return tuple(applied)
