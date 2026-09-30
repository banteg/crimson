from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.perks import PerkId, perk_display_description, perk_display_name
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import kill_creature, world_with_creature


def test_creature_handle_death_awards_bloody_mess_quick_learner_xp() -> None:
    player = PlayerState(index=0, pos=Vec2(), experience=100)
    world = world_with_creature(CreatureState(active=True, hp=10.0, reward_value=12.7), players=[player])
    world.state.bonus_spawn_guard = True
    world.state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    death = kill_creature(world)

    assert death.xp_awarded == 16  # int(12.7 * 1.3)
    assert player.experience == 116


def test_bloody_mess_quick_learner_name_depends_on_violence_disabled() -> None:
    perk_id = PerkId.BLOODY_MESS_QUICK_LEARNER
    assert perk_display_name(perk_id, violence_disabled=0) == "Bloody Mess"
    assert perk_display_name(perk_id, violence_disabled=1) == "Quick Learner"
    assert perk_display_description(perk_id, violence_disabled=1).startswith("You learn things faster")
