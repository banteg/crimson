from __future__ import annotations

"""Player damage intake helpers.

This is a minimal, rewrite-focused port of `player_take_damage` (0x00425e50).
See: `docs/crimsonland-exe/player-damage.md`.
"""

from typing import Callable

from .gameplay import GameplayState, PlayerState, perk_active
from .perks import PerkId

__all__ = ["player_take_damage", "player_take_projectile_damage"]
_PLAYER_PAIN_SFX: tuple[str, ...] = (
    "sfx_trooper_inpain_01",
    "sfx_trooper_inpain_02",
    "sfx_trooper_inpain_03",
)
_PLAYER_DEATH_SFX: tuple[str, ...] = ("sfx_trooper_die_01", "sfx_trooper_die_02")
_THICK_SKINNED_DAMAGE_SCALE_F32 = 0.6660000085830688


def player_take_damage(
    state: GameplayState,
    player: PlayerState,
    damage: float,
    *,
    dt: float | None = None,
    rand: Callable[[], int] | None = None,
) -> float:
    """Apply damage to a player, returning the actual damage applied."""

    raw_damage = float(damage)
    if raw_damage <= 0.0:
        return 0.0
    if state.debug_god_mode:
        return 0.0

    rng = rand or state.rng.rand

    if perk_active(player, PerkId.DEATH_CLOCK):
        return 0.0

    damage_scaled = float(raw_damage)
    if perk_active(player, PerkId.TOUGH_RELOADER) and bool(player.reload_active):
        damage_scaled *= 0.5

    if float(player.shield_timer) > 0.0:
        return 0.0

    was_alive = float(player.health) > 0.0

    if perk_active(player, PerkId.THICK_SKINNED):
        # Native uses an f32 constant (`~0.666`) here, not exact 2/3.
        damage_scaled *= _THICK_SKINNED_DAMAGE_SCALE_F32

    dodged = False
    if perk_active(player, PerkId.NINJA):
        dodged = (int(rng()) % 3) == 0
    elif perk_active(player, PerkId.DODGER):
        dodged = (int(rng()) % 5) == 0

    health_before = float(player.health)
    if not dodged:
        if perk_active(player, PerkId.HIGHLANDER):
            if (int(rng()) % 10) == 0:
                player.health = 0.0
        else:
            player.health -= float(damage_scaled)
            if player.health < 0.0 and dt is not None and float(dt) > 0.0:
                player.death_timer -= float(dt) * 28.0

    # Native emits pain/death VO before heading jitter + low-health timer RNG work.
    if player.health >= 0.0:
        state.sfx_queue.append(_PLAYER_PAIN_SFX[int(rng()) % len(_PLAYER_PAIN_SFX)])
        if not was_alive:
            return max(0.0, health_before - float(player.health))
    else:
        if not was_alive:
            return max(0.0, health_before - float(player.health))
        if not perk_active(player, PerkId.FINAL_REVENGE):
            state.sfx_queue.append(_PLAYER_DEATH_SFX[int(rng()) & 1])

    if not dodged:
        if not perk_active(player, PerkId.UNSTOPPABLE):
            player.heading += float((int(rng()) % 100) - 50) * 0.04
            # Native uses the raw incoming damage for spread heat growth.
            player.spread_heat = min(0.48, float(player.spread_heat) + raw_damage * 0.01)

        if player.health <= 20.0 and (int(rng()) & 7) == 3:
            player.low_health_timer = 0.0

    return max(0.0, health_before - float(player.health))


def player_take_projectile_damage(state: GameplayState, player: PlayerState, damage: float) -> float:
    """Apply projectile damage to a player (modeled after `projectile_update` player-hit logic).

    Native `projectile_update` does not call `player_take_damage` for projectile hits: it sets
    `projectile.life_timer = 0.25` and subtracts a fixed amount (usually 10.0) if shield is down.
    """

    dmg = float(damage)
    if dmg <= 0.0:
        return 0.0
    if state.debug_god_mode:
        return 0.0
    if float(player.shield_timer) > 0.0:
        return 0.0

    player.health -= dmg
    return dmg
