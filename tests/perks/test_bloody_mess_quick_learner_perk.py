from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId, perk_display_description, perk_display_name
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_creature_handle_death_awards_bloody_mess_quick_learner_xp() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True

    player = PlayerState(index=0, pos=Vec2(), experience=100)
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.reward_value = 12.7
    creature.last_hit_owner = OwnerRef.from_player(0)

    death = pool.handle_death(
        0,
        state=state,
        players=[player],
        rng=state.rng,
        world_width=1024.0,
        world_height=1024.0,
        fx_queue=None,
    )

    assert death.xp_awarded == 16  # int(12.7 * 1.3)
    assert player.experience == 116


def test_bloody_mess_quick_learner_name_depends_on_violence_disabled() -> None:
    perk_id = PerkId.BLOODY_MESS_QUICK_LEARNER
    assert perk_display_name(perk_id, violence_disabled=0) == "Bloody Mess"
    assert perk_display_name(perk_id, violence_disabled=1) == "Quick Learner"
    assert perk_display_description(perk_id, violence_disabled=1).startswith("You learn things faster")
