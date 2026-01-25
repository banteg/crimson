from __future__ import annotations

"""Player damage intake helpers.

This is a minimal, rewrite-focused port of `player_take_damage` (0x00425e50).
See: `docs/crimsonland-exe/player-damage.md`.
"""

from typing import Callable

from .gameplay import GameplayState, PlayerState, perk_active
from .perks import PerkId

__all__ = ["player_take_damage"]


def player_take_damage(
    state: GameplayState,
    player: PlayerState,
    damage: float,
    *,
    rand: Callable[[], int] | None = None,
) -> float:
    """Apply damage to a player, returning the actual damage applied.

    Notes:
    - This models only the must-have gates used by creature contact damage.
    - Dodge chances and low-health warning timers are not yet ported.
    """

    dmg = float(damage)
    if dmg <= 0.0:
        return 0.0

    # 1) Death Clock immunity.
    if perk_active(player, PerkId.DEATH_CLOCK):
        return 0.0

    # 2) Tough Reloader mitigation while reloading.
    if perk_active(player, PerkId.TOUGH_RELOADER) and bool(player.reload_active):
        dmg *= 0.5

    # 3) Shield immunity.
    if float(player.shield_timer) > 0.0:
        return 0.0

    # Damage scaling perks.
    if perk_active(player, PerkId.THICK_SKINNED):
        dmg *= 2.0 / 3.0

    # Dodge perks: TODO (needs exact RNG/thresholds).
    _ = rand  # keep signature for future parity work

    player.health -= dmg
    return dmg

