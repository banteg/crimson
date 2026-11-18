"""The measured muzzle mount shared by presentation and the smoke event producer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2

if TYPE_CHECKING:
    from .sim.state_types import PlayerState

# Barrel tips in the fifteen 64-pixel torso cells. Also in game/rtx_barrel.h.
_FORWARD = (22.5, 21.5, 20.5, 19.5, 20.5, 20.5, 21.5, 22.5, 22.5, 23.5, 22.5, 22.5, 22.5, 22.5, 22.5)
_SIDE = (-2.83, -3.26, -3.70, -3.70, -3.56, -3.23, -3.00, -2.78, -2.65, -2.60, -2.59, -2.60, -2.61, -2.73, -2.79)


def barrel_position(player: PlayerState) -> Vec2:
    """The sprite's barrel tip in world coordinates, including the torso recoil."""
    frame = max(0, min(14, int(player.move_phase + 0.5)))
    forward = Vec2.from_heading(player.aim_heading)
    scale = player.size / 64.0
    distance = _FORWARD[frame] * scale - 12.0 * player.muzzle_flash_alpha
    return player.pos + forward * distance + forward.perp_left() * (_SIDE[frame] * scale)
