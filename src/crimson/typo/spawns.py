from __future__ import annotations

from typing import TYPE_CHECKING

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.lifecycle import CREATURE_LIFECYCLE_ALIVE
from ..creatures.spawn import CreatureAiMode, CreatureFlags, CreatureTypeId
from ..math_parity import f32, f32_vec2, x87_pc24_mul
from ..rng_caller_static import RngCallerStatic

if TYPE_CHECKING:
    from ..sim.world_state import WorldState


def creature_spawn_tinted(world: WorldState, pos: Vec2, tint: RGBA, type_id: CreatureTypeId) -> int:
    """Port of `creature_spawn_tinted` (0x00444810): a one-hit Typ-o creature chasing the player.

    Float fields store float literals, each x87 op rounded at PC24.
    """

    pool = world.creatures
    rng = world.state.rng
    creature_idx = pool.alloc_slot(rng)
    creature = pool.creature(creature_idx)
    creature.pos = f32_vec2(pos)
    creature.active = True
    creature.vel = Vec2()
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.plague_infected = False
    creature.dot_tick_timer = 0.0
    creature.type_id = type_id
    creature.force_target = 0
    creature.death_timer = CREATURE_LIFECYCLE_ALIVE
    creature.hp = 1.0
    heading_roll = rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING)
    creature.move_speed = f32(1.7)
    creature.reward_value = 1.0
    creature.attack_cooldown = 0.0
    creature.heading = x87_pc24_mul(float(heading_roll % 314), f32(0.01))
    creature.tint = RGBA(f32(tint.r), f32(tint.g), f32(tint.b), f32(tint.a))
    size_roll = rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE)
    creature.contact_damage = 100.0
    creature.max_hp = creature.hp
    size = float(size_roll % 20 + 47)
    creature.size = size
    if type_id in (CreatureTypeId.SPIDER_SP1, CreatureTypeId.SPIDER_SP2):
        creature.flags |= CreatureFlags.STOP_AND_GO
        creature.move_speed = x87_pc24_mul(creature.move_speed, f32(1.2))
        creature.size = x87_pc24_mul(size, f32(0.8))
    return creature_idx
