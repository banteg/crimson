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
    dt: float | None = None,
    rand: Callable[[], int] | None = None,
) -> float:
    """Apply damage to a player, returning the actual damage applied.

    Notes:
    - This models only the must-have gates used by creature contact damage.
    - Low-health warning timers are not yet ported.
    """

    dmg = float(damage)
    if dmg <= 0.0:
        return 0.0
    if state.debug_god_mode:
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

    rng = rand or state.rng.rand
    if perk_active(player, PerkId.NINJA):
        if (rng() % 3) == 0:
            return 0.0
    elif perk_active(player, PerkId.DODGER):
        if (rng() % 5) == 0:
            return 0.0

    health_before = float(player.health)

    if perk_active(player, PerkId.HIGHLANDER):
        if (rng() % 10) == 0:
            player.health = 0.0
    else:
        player.health -= dmg
        if player.health < 0.0 and dt is not None and float(dt) > 0.0:
            player.death_timer -= float(dt) * 28.0

    if not perk_active(player, PerkId.UNSTOPPABLE):
        # player_take_damage @ 0x00425e50: on-hit camera/spread disruption.
        player.heading += float((rng() % 100) - 50) * 0.04
        player.spread_heat = min(0.48, float(player.spread_heat) + dmg * 0.01)

    if player.health <= 20.0 and (rng() & 7) == 3:
        player.low_health_timer = 0.0
    return max(0.0, health_before - float(player.health))
