from __future__ import annotations

from typing import TYPE_CHECKING

from grim.color import RGBA
from grim.geom import Vec2

from ..creatures.spawn import CreatureAiMode, CreatureFlags, CreatureInit, CreatureTypeId
from ..math_parity import f32, x87_pc24_mul
from ..rng_caller_static import RngCallerStatic

if TYPE_CHECKING:
    from ..sim.world_state import WorldState


def creature_spawn_tinted(world: WorldState, pos: Vec2, tint: RGBA, type_id: CreatureTypeId) -> int | None:
    """Port of `creature_spawn_tinted` (0x00444810): a one-hit Typ-o creature chasing the player.

    Float fields store float literals, each x87 op rounded at PC24.
    """

    rng = world.state.rng
    # `creature_alloc_slot` seeds phase_seed = crt_rand() & 0x17f before the heading and size draws.
    phase_seed = rng.rand_tagged(RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED) & 0x17F
    heading = x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_HEADING) % 314), f32(0.01))
    size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TINTED_SIZE) % 20 + 47)
    flags = CreatureFlags(0)
    move_speed = f32(1.7)
    if type_id in (CreatureTypeId.SPIDER_SP1, CreatureTypeId.SPIDER_SP2):
        flags |= CreatureFlags.AI7_LINK_TIMER
        move_speed = x87_pc24_mul(move_speed, f32(1.2))
        size = x87_pc24_mul(size, f32(0.8))
    return world.creatures.spawn_init(
        CreatureInit(
            origin_template_id=0,
            pos=pos,
            heading=heading,
            phase_seed=phase_seed,
            type_id=type_id,
            flags=flags,
            ai_mode=CreatureAiMode.CHASE_PLAYER,
            health=1.0,
            max_health=1.0,
            move_speed=move_speed,
            reward_value=1.0,
            size=size,
            contact_damage=100.0,
            tint=tint.to_tuple(),
        ),
    )
