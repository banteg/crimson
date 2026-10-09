from __future__ import annotations

from crimson.creatures.anim import (
    CREATURE_ANIM,
    creature_anim_advance_phase,
)
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue, FxQueueRotated
from crimson.owner_id import player_owner_id
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import player_input


def test_creature_killed_by_a_projectile_still_advances_its_walk_cycle_that_tick() -> None:
    # Native advances anim_phase inside `creature_update_all`, which runs before
    # `projectile_update`; a creature shot dead later in the tick keeps that step.
    world = WorldState.build(hardcore=False, quest_fail_retry_count=0)
    world.players.append(PlayerState(index=0, pos=Vec2(512.0, 512.0)))
    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.ALIEN
    creature.flags = CreatureFlags(0)
    creature.pos = Vec2(256.0, 256.0)
    creature.hp = 1.0
    creature.max_hp = 1.0
    creature.size = 50.0
    creature.move_speed = 2.0
    creature.death_timer = 16.0
    projectile_spawn(
        world.state,
        players=world.players,
        pos=creature.pos,
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=player_owner_id(0),
        owner_player_index=0,
    )
    dt = 1.0 / 60.0

    events = world.step(
        dt,
        inputs=[player_input() for _ in world.players],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert [death.index for death in events.deaths] == [0]
    expected_phase, _step = creature_anim_advance_phase(
        0.0,
        anim_rate=CREATURE_ANIM[CreatureTypeId.ALIEN].anim_rate,
        move_speed=2.0,
        dt=dt,
        size=50.0,
    )
    assert expected_phase > 0.0
    assert creature.anim_phase == expected_phase
