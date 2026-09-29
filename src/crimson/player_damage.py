"""Player damage intake helpers.

This is a minimal, rewrite-focused port of `player_take_damage` (0x00425e50).
See: `docs/crimsonland-exe/player-damage.md`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from .creatures.damage import creature_apply_damage
from .creatures.damage_types import CreatureDamageType
from .math_parity import f32, x87_pc24_add, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from .owner_id import player_owner_id
from .perks import PerkId
from .rng_caller_static import RngCallerStatic
from .sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState
    from crimson.sim.world_state import WorldStepRuntime


__all__ = ["player_take_damage", "player_take_projectile_damage"]
_PLAYER_PAIN_SFX: tuple[SfxId, ...] = (
    SfxId.TROOPER_INPAIN_01,
    SfxId.TROOPER_INPAIN_02,
    SfxId.TROOPER_INPAIN_03,
)
_PLAYER_DEATH_SFX: tuple[SfxId, ...] = (SfxId.TROOPER_DIE_01, SfxId.TROOPER_DIE_02)
_THICK_SKINNED_DAMAGE_SCALE_F32 = 0.6660000085830688


def _final_revenge(step_runtime: WorldStepRuntime, player: PlayerState) -> None:
    """The Final Revenge blast of native `player_take_damage`: 5 damage per unit inside 512 of the dying player."""

    world = step_runtime.world
    state = world.state
    state.effects.spawn_explosion_burst(
        pos=player.pos, scale=1.8, rng=state.rng, detail_preset=step_runtime.world.state.detail_preset,
    )
    state.bonus_spawn_guard = True
    for creature_idx, creature in enumerate(world.creatures.entries):
        if not creature.active:
            continue
        dx = x87_pc24_sub(creature.pos.x, player.pos.x)
        dy = x87_pc24_sub(creature.pos.y, player.pos.y)
        if abs(dx) > 512.0 or abs(dy) > 512.0:
            continue
        blast = x87_pc24_sub(512.0, x87_pc24_hypot(dx, dy))
        if blast <= 0.0:
            continue
        creature_apply_damage(
            step_runtime,
            creature_idx,
            x87_pc24_mul(blast, 5.0),
            CreatureDamageType.EXPLOSION,
            Vec2(),
            player_owner_id(player.index),
        )
    state.bonus_spawn_guard = False
    state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_LARGE, player.pos))
    state.sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, player.pos))


def player_take_damage(step_runtime: WorldStepRuntime, player: PlayerState, damage: float, *, dt: float) -> float:
    """Port of `player_take_damage`, returning the actual damage applied."""

    state = step_runtime.world.state
    players = step_runtime.world.players
    raw_damage = f32(damage)
    if state.debug_god_mode:
        return 0.0

    if PerkId.DEATH_CLOCK in state.perks:
        return 0.0

    damage_scaled = float(raw_damage)
    if PerkId.TOUGH_RELOADER in state.perks and player.weapon.reload_active:
        damage_scaled = x87_pc24_mul(damage_scaled, f32(0.5))
    spread_heat_damage = float(damage_scaled)

    state.survival_reward_damage_seen = True

    if float(player.shield_timer) > 0.0:
        return 0.0

    # Native reads player one's health here whichever player takes the damage.
    was_alive_player = players[0] if state.preserve_bugs else player
    was_alive = float(was_alive_player.health) > 0.0

    if PerkId.THICK_SKINNED in state.perks:
        # Native uses an f32 constant (`~0.666`) here, not exact 2/3.
        damage_scaled = f32(float(damage_scaled) * float(_THICK_SKINNED_DAMAGE_SCALE_F32))

    dodged = False
    if PerkId.NINJA in state.perks:
        dodged = (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_NINJA) % 3) == 0
    elif PerkId.DODGER in state.perks:
        dodged = (state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_DODGER) % 5) == 0

    health_before = float(player.health)
    if not dodged:
        if PerkId.HIGHLANDER in state.perks:
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
    if lethal_hit and float(dt) > 0.0:
        player.death_timer = x87_pc24_sub(
            f32(player.death_timer),
            x87_pc24_mul(f32(dt), f32(28.0)),
        )

    # Native emits pain/death VO before heading jitter + low-health timer RNG work.
    if not lethal_hit:
        state.sfx_queue.append(
            SfxRequest(
                _PLAYER_PAIN_SFX[
                    state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX) % len(_PLAYER_PAIN_SFX)
                ],
                player.pos,
            ),
        )
        if not was_alive:
            return max(0.0, health_before - float(player.health))
    else:
        if not was_alive:
            return max(0.0, health_before - float(player.health))
        if PerkId.FINAL_REVENGE not in state.perks:
            state.sfx_queue.append(
                SfxRequest(
                    _PLAYER_DEATH_SFX[state.rng.rand_tagged(RngCallerStatic.PLAYER_TAKE_DAMAGE_DEATH_SFX) & 1],
                    player.pos,
                ),
            )
        else:
            _final_revenge(step_runtime, player)

    if not dodged:
        if PerkId.UNSTOPPABLE not in state.perks:
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
    # Original bug #27: native skips the Death Clock immunity here.
    if PerkId.DEATH_CLOCK in state.perks and not state.preserve_bugs:
        return 0.0
    if float(player.shield_timer) > 0.0:
        return 0.0

    player.health -= dmg
    return dmg
