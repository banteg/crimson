"""Modern controller profile, applied the first time a player on stock bindings uses a pad.

The stock `crimson.cfg` bindings are the original's DirectInput-era defaults
(swapped `JoyAxis*` aim axes, `JoyAxisZ`/`JoyRotX` movement), which put a modern
controller's movement on the wrong stick.  When a player whose bindings are still
exactly those defaults touches their pad, the player is switched to twin-stick
controls in standard controller codes and the config is saved.  The switch is an
ordinary config edit: it shows in Controls, and any later change there (for
example picking Mouse aim again) leaves the player customized, so it never
re-triggers.
"""

from __future__ import annotations

from collections.abc import Callable

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


def player_bindings_are_stock(controls: CrimsonControlsConfig, player_index: int) -> bool:
    stock = default_player_controls(player_index)
    player = controls.player(player_index)
    # The direction-arrow toggle is a HUD preference, not a binding.
    return msgspec.structs.replace(player, show_direction_arrow=stock.show_direction_arrow) == stock


def apply_pad_profile(controls: CrimsonControlsConfig, player_index: int) -> None:
    """Switch one player to twin-stick pad controls.

    Keyboard codes stay as they are, so picking a keyboard movement method later
    brings the stock keys back.  Reload and Level Up are global codes owned by
    player 1 (the Controls menu edits them there); they move to the pad only if
    still at their stock mouse buttons.
    """

    player = controls.player(player_index)
    player.movement = MovementControlType.DUAL_ACTION_PAD
    player.aim_scheme = AimScheme.DUAL_ACTION_PAD
    player.move_axis_codes = PAD_PROFILE_MOVE_AXIS_CODES
    player.aim_axis_codes = PAD_PROFILE_AIM_AXIS_CODES
    player.fire_code = PAD_PROFILE_FIRE_CODE
    if int(player_index) != 0:
        return
    if controls.reload_code == DEFAULT_RELOAD_CODE:
        controls.reload_code = PAD_PROFILE_RELOAD_CODE
    if controls.pick_perk_code == DEFAULT_PICK_PERK_CODE:
        controls.pick_perk_code = PAD_PROFILE_PICK_PERK_CODE


def auto_apply_pad_profiles(
    controls: CrimsonControlsConfig,
    *,
    player_count: int,
    pad_active: Callable[[int], bool] = gamepad_has_activity,
) -> tuple[int, ...]:
    """Apply the pad profile to each active stock-bound player whose pad is in use.

    Returns the switched player indices; the caller persists the config.
    """

    switched: list[int] = []
    for player_index in range(max(1, min(len(controls.players), int(player_count)))):
        if not player_bindings_are_stock(controls, player_index):
            continue
        if not pad_active(player_gamepad_index(player_index)):
            continue
        apply_pad_profile(controls, player_index)
        switched.append(player_index)
    return tuple(switched)
