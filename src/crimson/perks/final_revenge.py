from __future__ import annotations

from grim.geom import Vec2

from ..creatures.damage import creature_apply_damage
from ..creatures.runtime import CREATURE_HITBOX_ALIVE, CreatureDeath, CreaturePool
from ..effects import FxQueue
from ..gameplay import GameplayState, PlayerState, perk_active
from .ids import PerkId


def apply_final_revenge_on_player_death(
    *,
    state: GameplayState,
    creatures: CreaturePool,
    players: list[PlayerState],
    player: PlayerState,
    dt: float,
    world_size: float,
    detail_preset: int,
    fx_queue: FxQueue,
    deaths: list[CreatureDeath],
) -> None:
    """Apply Final Revenge perk behavior when a player dies."""
    if not perk_active(player, PerkId.FINAL_REVENGE):
        return

    player_pos = player.pos
    rand = state.rng.rand
    state.effects.spawn_explosion_burst(
        pos=player_pos,
        scale=1.8,
        rand=rand,
        detail_preset=int(detail_preset),
    )

    prev_guard = bool(state.bonus_spawn_guard)
    state.bonus_spawn_guard = True
    for creature_idx, creature in enumerate(creatures.entries):
        if not creature.active:
            continue
        if float(creature.hp) <= 0.0:
            continue

        delta = creature.pos - player_pos
        if abs(delta.x) > 512.0 or abs(delta.y) > 512.0:
            continue

        remaining = 512.0 - delta.length()
        if remaining <= 0.0:
            continue

        damage = remaining * 5.0
        death_start_needed = float(creature.hp) > 0.0 and float(creature.hitbox_size) == CREATURE_HITBOX_ALIVE
        killed = creature_apply_damage(
            creature,
            damage_amount=damage,
            damage_type=3,
            impulse=Vec2(),
            owner_id=-1 - int(player.index),
            dt=float(dt),
            players=players,
            rand=rand,
        )
        if killed and death_start_needed:
            deaths.append(
                creatures.handle_death(
                    int(creature_idx),
                    state=state,
                    players=players,
                    rand=rand,
                    dt=float(dt),
                    detail_preset=int(detail_preset),
                    world_width=float(world_size),
                    world_height=float(world_size),
                    fx_queue=fx_queue,
                )
            )

    state.bonus_spawn_guard = prev_guard
    state.sfx_queue.append("sfx_explosion_large")
    state.sfx_queue.append("sfx_shockwave")
