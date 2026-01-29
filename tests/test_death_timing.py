from __future__ import annotations

from crimson.creatures.runtime import CreatureDeath
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerState
from crimson.projectiles import ProjectileTypeId
from crimson.sim.world_state import WorldState


def test_projectile_kill_awards_xp_same_step() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )
    player = PlayerState(index=0, pos_x=512.0, pos_y=512.0)
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.x = 100.0
    creature.y = 100.0
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.hp = 1.0
    creature.max_hp = 1.0
    creature.reward_value = 10.0

    world.state.projectiles.spawn(
        pos_x=float(creature.x),
        pos_y=float(creature.y),
        angle=0.0,
        type_id=int(ProjectileTypeId.PISTOL),
        owner_id=-1,
    )

    assert player.experience == 0
    events = world.step(
        0.016,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        auto_pick_perks=False,
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )
    assert player.experience == 10
    assert len(events.deaths) == 1
    assert isinstance(events.deaths[0], CreatureDeath)
    assert events.deaths[0].xp_awarded == 10
