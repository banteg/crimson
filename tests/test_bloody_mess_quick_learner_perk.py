from __future__ import annotations

from crimson.creatures.runtime import CREATURE_HITBOX_ALIVE, CreaturePool
from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId


def test_creature_handle_death_awards_bloody_mess_quick_learner_xp() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True

    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, experience=100)
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

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

    assert death.xp_awarded == 16  # int(12.7 * 1.3)
    assert player.experience == 116

