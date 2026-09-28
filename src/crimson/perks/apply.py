from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PlayerState
from ..weapon_runtime.assign import weapon_assign_player
from ..weapon_runtime.availability import weapon_pick_random_available
from ..weapons import WeaponId
from .ids import PerkId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState

# Native f32 literals.
_THICK_SKINNED_FRACTION = f32(0.33333334)
_BREATHING_ROOM_FRACTION = f32(0.6666667)
_GRIM_DEAL_XP_SCALE = f32(0.18)


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    dt: float = 0.0,
    creatures: Sequence[CreatureState] = (),
) -> None:
    """Port of `perk_apply`: count the perk, then run its immediate effect."""

    state.perks[perk_id] += 1
    owner = players[0]

    match perk_id:
        case PerkId.INSTANT_WINNER:
            owner.experience += 2500

        case PerkId.FATAL_LOTTERY:
            if state.rng.rand_tagged(RngCallerStatic.PERK_APPLY_FATAL_LOTTERY) & 1:
                owner.health = -1.0
            else:
                owner.experience += 10000

        case PerkId.LIFELINE_50_50:
            for index, creature in enumerate(creatures):
                if index & 1 and creature.active and float(creature.hp) <= 500.0 and (int(creature.flags) & 0x04) == 0:
                    creature.active = False
                    state.effects.spawn_burst(pos=creature.pos, count=4, rng=state.rng, detail_preset=5)

        case PerkId.THICK_SKINNED:
            for player in players:
                if player.health > 0.0:
                    # Native's `= 1.0` clamp for results <= 0 is unreachable for positive health.
                    health = f32(player.health)
                    player.health = x87_pc24_sub(health, x87_pc24_mul(health, _THICK_SKINNED_FRACTION))

        case PerkId.BREATHING_ROOM:
            for player in players:
                health = f32(player.health)
                player.health = x87_pc24_sub(health, x87_pc24_mul(health, _BREATHING_ROOM_FRACTION))
            frame_dt = f32(dt)
            for creature in creatures:
                if creature.active:
                    creature.lifecycle_stage = x87_pc24_sub(f32(creature.lifecycle_stage), frame_dt)
            state.bonus_spawn_guard = False

        case PerkId.RANDOM_WEAPON:
            current = owner.weapon.weapon_id
            weapon_id = current
            for _ in range(100):
                weapon_id = weapon_pick_random_available(state)
                if weapon_id != WeaponId.PISTOL and weapon_id != current:
                    break
            weapon_assign_player(owner, weapon_id, state=state)

        case PerkId.INFERNAL_CONTRACT:
            owner.level += 3
            state.perk_selection.pending_count += 3
            state.perk_selection.choices_dirty = True
            # Native sets the two player slots it has; the co-op fix covers every player.
            for player in players[:2] if state.preserve_bugs else players:
                if player.health > 0.0:
                    player.health = f32(0.1)

        case PerkId.GRIM_DEAL:
            experience = int(owner.experience)
            owner.health = -1.0
            owner.experience = experience + int(x87_pc24_mul(float(experience), _GRIM_DEAL_XP_SCALE))

        case PerkId.AMMO_MANIAC:
            for player in players:
                weapon_assign_player(player, WeaponId(player.weapon.weapon_id), state=state)

        case PerkId.DEATH_CLOCK:
            state.perks[PerkId.GREATER_REGENERATION] = 0
            state.perks[PerkId.REGENERATION] = 0
            for player in players:
                if player.health > 0.0:
                    player.health = 100.0

        case PerkId.BANDAGE:
            for player in players:
                # Native heals dead players too (their negative health gets
                # multiplied); the default mode heals only the living
                # (original-bugs.md item 3).
                if not state.preserve_bugs and player.health <= 0.0:
                    continue
                amount = float(state.rng.rand_tagged(RngCallerStatic.PERK_APPLY_BANDAGE_HEAL) % 50 + 1)
                health = f32(player.health)
                if state.preserve_bugs:
                    # Native multiplies health by the roll.
                    player.health = min(100.0, x87_pc24_mul(health, amount))
                else:
                    # The perk text promises restoring up to 50% health.
                    player.health = min(100.0, x87_pc24_add(health, amount))
                state.effects.spawn_burst(pos=player.pos, count=8, rng=state.rng, detail_preset=5)

        case PerkId.MY_FAVOURITE_WEAPON:
            for player in players:
                player.weapon.clip_size += 2

        case PerkId.PLAGUEBEARER:
            # Native flags only player one; the co-op fix flags every player.
            for player in players[:1] if state.preserve_bugs else players:
                player.plaguebearer_active = True
