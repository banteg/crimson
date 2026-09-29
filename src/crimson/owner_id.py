"""Native `owner_id` of projectiles, effects and a creature's last hit.

A creature index (>= 0), a player as `-1 - player_index`, or -100: the local player's shots with friendly fire
off, which never hit players.
"""

from __future__ import annotations

OWNER_LOCAL_PLAYER = -100


def player_owner_id(player_index: int) -> int:
    return -1 - player_index


def player_projectile_owner_id(*, friendly_fire: bool, player_index: int) -> int:
    """The owner a player's shots carry: their own id only when they may hit other players."""
    return player_owner_id(player_index) if friendly_fire else OWNER_LOCAL_PLAYER
