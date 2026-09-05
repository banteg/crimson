from __future__ import annotations

from typing import TYPE_CHECKING

"""Player damage intake helpers.

This is a minimal, rewrite-focused port of `player_take_damage` (0x00425e50).
See: `docs/crimsonland-exe/player-damage.md`.
"""

from collections.abc import Sequence

import msgspec

from grim.sfx_map import SfxId

from .math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from .perks import PerkId
from .perks.helpers import perk_active
from .rng_caller_static import RngCallerStatic
from .sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


__all__ = ["PlayerDeathRuntime", "player_take_damage", "player_take_projectile_damage"]
_PLAYER_PAIN_SFX: tuple[SfxId, ...] = (
    SfxId.TROOPER_INPAIN_01,
    SfxId.TROOPER_INPAIN_02,
    SfxId.TROOPER_INPAIN_03,
)
_PLAYER_DEATH_SFX: tuple[SfxId, ...] = (SfxId.TROOPER_DIE_01, SfxId.TROOPER_DIE_02)
_THICK_SKINNED_DAMAGE_SCALE_F32 = 0.6660000085830688


class PlayerDeathRuntime(msgspec.Struct):
    def on_player_lethal(self, player: PlayerState, *, dt: float) -> None:
        _ = player, dt


def player_take_damage(
    state: GameplayState,
    player: PlayerState,
    damage: float,
    *,
    dt: float | None = None,
    players: Sequence[PlayerState] | None = None,
    death_runtime: PlayerDeathRuntime | None = None,
) -> float:
    """Apply damage to a player, returning the actual damage applied."""

    raw_damage = float(f32(damage))
    if state.debug_god_mode:
        return 0.0

    # Native perk_count_get() is hard-wired to player 1 even though the
    # surrounding player fields are indexed by the actual damage target.
    perk_player = players[0] if state.preserve_bugs and players else player

    if perk_active(perk_player, PerkId.DEATH_CLOCK):
        return 0.0

    damage_scaled = float(raw_damage)
    if perk_active(perk_player, PerkId.TOUGH_RELOADER) and player.weapon.reload_active:
        damage_scaled = x87_pc24_mul(damage_scaled, f32(0.5))
    spread_heat_damage = float(damage_scaled)

    state.survival_reward_damage_seen = True

    if float(player.shield_timer) > 0.0:
        return 0.0

    was_alive = float(perk_player.health) > 0.0

    if perk_active(perk_player, PerkId.THICK_SKINNED):
        # Native uses an f32 constant (`~0.666`) here, not exact 2/3.
        damage_scaled = float(f32(float(damage_scaled) * float(_THICK_SKINNED_DAMAGE_SCALE_F32)))

    dodged = False
    if perk_active(perk_player, PerkId.NINJA):
        dodged = (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_NINJA) % 3) == 0
    elif perk_active(perk_player, PerkId.DODGER):
        dodged = (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_DODGER) % 5) == 0

    health_before = float(player.health)
    if not dodged:
        if perk_active(perk_player, PerkId.HIGHLANDER):
            if (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_HIGHLANDER) % 10) == 0:
                player.health = 0.0
        else:
            player.health = x87_pc24_sub(f32(player.health), damage_scaled)

    # Native routes exact-zero Highlander kills through the pain branch; default
    # rewrite mode treats `health == 0` as lethal here.
    lethal_hit = float(player.health) < 0.0
    if not state.preserve_bugs and float(player.health) == 0.0:
        lethal_hit = True
    # Native's dodge proc jumps past the damage stores but still runs the
    # health branch: a dodged hit on an already-dead player keeps decrementing
    # the death-animation timer.
    if lethal_hit and dt is not None and float(dt) > 0.0:
        player.death_timer = x87_pc24_sub(
            f32(player.death_timer),
            x87_pc24_mul(f32(dt), f32(28.0)),
        )

    # Native emits pain/death VO before heading jitter + low-health timer RNG work.
    if not lethal_hit:
        state.sfx_queue.append(
            _PLAYER_PAIN_SFX[state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX) % len(_PLAYER_PAIN_SFX)],
        )
        if not was_alive:
            return max(0.0, health_before - float(player.health))
    else:
        if not was_alive:
            return max(0.0, health_before - float(player.health))
        if not perk_active(perk_player, PerkId.FINAL_REVENGE):
            state.sfx_queue.append(_PLAYER_DEATH_SFX[state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_DEATH_SFX) & 1])
        elif death_runtime is not None:
            death_runtime.on_player_lethal(player, dt=0.0 if dt is None else float(dt))

    if not dodged:
        if not perk_active(perk_player, PerkId.UNSTOPPABLE):
            heading_jitter = x87_pc24_mul(
                float((state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_HEADING) % 100) - 50),
                f32(0.04),
            )
            player.heading = x87_pc24_add(f32(player.heading), heading_jitter)
            # Native uses post-Tough-Reloader damage (before Thick Skinned) for spread heat growth.
            player.spread_heat = min(
                f32(0.48),
                x87_pc24_add(
                    player.spread_heat,
                    x87_pc24_mul(spread_heat_damage, f32(0.01)),
                ),
            )

        if player.health <= 20.0 and (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_LOW_HEALTH) & 7) == 3:
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
