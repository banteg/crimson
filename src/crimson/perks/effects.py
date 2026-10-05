from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..collision_math import creature_find_in_radius
from ..effects import FxQueue
from ..gameplay import experience_plus_reward
from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PlayerState
from .ids import PerkId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState


def perks_update_effects(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[CreatureState],
    fx_queue: FxQueue,
) -> None:
    """Port of `perks_update_effects` (0x00406b40).

    Native targets player one throughout; the rewrite (without `preserve_bugs`) gives every live
    player the same treatment.
    """

    if dt <= 0.0:
        return
    dt = f32(dt)
    perks = state.perks
    rng = state.rng

    if PerkId.REGENERATION in perks and rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_REGENERATION_GATE) & 1:
        if state.preserve_bugs:
            # Native heals player one only, once per `config_player_count`.
            player0 = players[0]
            for _ in players:
                if 0.0 < player0.health < 100.0:
                    player0.health = min(100.0, x87_pc24_add(f32(player0.health), dt))
        else:
            # Native no-ops Greater Regeneration; the rewrite doubles the heal.
            heal = x87_pc24_mul(dt, f32(2.0)) if PerkId.GREATER_REGENERATION in perks else dt
            for player in players:
                if 0.0 < player.health < 100.0:
                    player.health = min(100.0, x87_pc24_add(f32(player.health), heal))

    state.lean_mean_exp_timer = x87_pc24_sub(f32(state.lean_mean_exp_timer), dt)
    if state.lean_mean_exp_timer < 0.0:
        state.lean_mean_exp_timer = f32(0.25)
        perk_count = perks[PerkId.LEAN_MEAN_EXP_MACHINE]
        if perk_count > 0:
            players[0].experience += perk_count * 10

    death_clock_drain = x87_pc24_mul(dt, f32(3.33333325))
    for player in players:
        if PerkId.DEATH_CLOCK in perks:
            if player.health > 0.0:
                player.health = x87_pc24_sub(f32(player.health), death_clock_drain)
            else:
                player.health = 0.0

        if player.shield_timer > 0.0:
            player.shield_timer = x87_pc24_sub(f32(player.shield_timer), dt)
        else:
            player.shield_timer = 0.0

        if player.fire_bullets_timer > 0.0:
            player.fire_bullets_timer = x87_pc24_sub(f32(player.fire_bullets_timer), dt)
        else:
            player.fire_bullets_timer = 0.0

        if player.speed_bonus_timer > 0.0:
            player.speed_bonus_timer = x87_pc24_sub(f32(player.speed_bonus_timer), dt)
        else:
            player.speed_bonus_timer = 0.0

    for player in players[:1] if state.preserve_bugs else players:
        player.doctor_target_creature = -1
        player.evil_eyes_target_creature = -1
        if not state.preserve_bugs and player.health <= 0.0:
            continue
        if not (PerkId.DOCTOR in perks or PerkId.PYROKINETIC in perks or PerkId.EVIL_EYES in perks):
            continue
        creature_id = creature_find_in_radius(creatures, pos=player.aim, radius=12.0, start_index=0)
        if creature_id == -1:
            continue

        if PerkId.DOCTOR in perks:
            player.doctor_target_creature = creature_id

        if PerkId.PYROKINETIC in perks:
            creature = creatures[creature_id]
            creature.dot_tick_timer = x87_pc24_sub(f32(creature.dot_tick_timer), dt)
            if creature.dot_tick_timer < 0.0:
                creature.dot_tick_timer = 0.5
                for intensity, caller in (
                    (0.8, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P8),
                    (0.6, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P6),
                    (0.4, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P4),
                    (0.3, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P3),
                    (0.2, RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P2),
                ):
                    angle = x87_pc24_mul(float(rng.rand_tagged(caller) % 628), f32(0.01))
                    state.particles.spawn_particle(pos=creature.pos, angle=angle, intensity=intensity, rng=rng)
                fx_queue.add_random(pos=creature.pos, rng=rng)

        if PerkId.EVIL_EYES in perks:
            player.evil_eyes_target_creature = creature_id

    if state.jinxed_timer >= 0.0:
        state.jinxed_timer = x87_pc24_sub(f32(state.jinxed_timer), dt)
    if state.jinxed_timer >= 0.0 or PerkId.JINXED not in perks:
        return

    if rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_ACCIDENT_GATE) % 10 == 3:
        # Native always hurts player one; the rewrite picks among the live players.
        victim = players[0]
        if not state.preserve_bugs:
            alive_players = [player for player in players if player.health > 0.0]
            if len(alive_players) == 1:
                victim = alive_players[0]
            elif alive_players:
                pick = rng.rand_tagged(RngCallerStatic.REWRITE_JINXED_ACCIDENT_TARGET_PICK) % len(alive_players)
                victim = alive_players[pick]
        victim.health = x87_pc24_sub(f32(victim.health), f32(5.0))
        fx_queue.add_random(pos=victim.pos, rng=rng)
        fx_queue.add_random(pos=victim.pos, rng=rng)

    timer_roll = float(rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_TIMER_RESET) % 20)
    state.jinxed_timer = x87_pc24_add(
        x87_pc24_add(x87_pc24_mul(timer_roll, f32(0.1)), f32(state.jinxed_timer)),
        f32(2.0),
    )

    if state.bonuses.freeze > 0.0:
        return

    # Native rolls `% 0x17f`, so the last pool slot is never picked.
    pool_mod = 0x17F if state.preserve_bugs else 0x180
    creature_id = rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_PICK) % pool_mod
    attempts = 0
    while attempts < 10 and not creatures[creature_id].active:
        creature_id = rng.rand_tagged(RngCallerStatic.PERKS_UPDATE_EFFECTS_JINXED_CREATURE_RETRY) % pool_mod
        attempts += 1
    creature = creatures[creature_id]
    if not creature.active:
        return

    creature.hp = -1.0
    creature.death_timer = x87_pc24_sub(f32(creature.death_timer), x87_pc24_mul(dt, f32(20.0)))
    # Native adds the reward once (0x004070a6: `fild`, one PC24 `fadd`, `__ftol`): unlike
    # creature_handle_death, the Jinxed kill ignores Double Experience.
    players[0].experience = experience_plus_reward(players[0].experience, creature.reward_value)
    state.sfx_queue.append(SfxRequest(SfxId.TROOPER_INPAIN_01, creature.pos))
