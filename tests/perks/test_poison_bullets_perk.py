from __future__ import annotations

from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.perks import PerkId
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import player_input
from tests.support.helpers import ScriptedCrand


def test_poison_bullets_with_toxic_avenger_still_sets_only_weak_poison_on_bullet_hit() -> None:
    world = WorldState.build(
        hardcore=False,
        quest_fail_retry_count=0,
    )
    world.state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # rand & 7 == 1

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    world.state.perks[int(PerkId.POISON_BULLETS)] = 1
    world.state.perks[int(PerkId.TOXIC_AVENGER)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.SPAWNER
    creature.pos = Vec2(300.0, 300.0)
    creature.hp = 1000.0
    creature.max_hp = 1000.0

    projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(creature.pos.x, creature.pos.y),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=0,
    )

    world.step(
        0.016,
        inputs=[player_input()],
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert creature.flags & CreatureFlags.POISONED
    assert not (creature.flags & CreatureFlags.POISONED_STRONG)
