from __future__ import annotations

from grim.geom import Vec2

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.gameplay import GameplayState, PlayerState


def test_creature_handle_death_doubles_xp_when_double_xp_bonus_active() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), experience=100)

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.hitbox_size = CREATURE_HITBOX_ALIVE
    creature.reward_value = 12.7
    creature.last_hit_owner_id = -1

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rand=lambda: 0,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    assert death.xp_awarded == 24  # 2 * int(12.7)
    assert player.experience == 124

