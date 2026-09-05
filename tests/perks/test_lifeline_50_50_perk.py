from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


def test_perk_apply_lifeline_50_50_deactivates_every_other_eligible_creature_slot() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())

    creatures: list[CreatureState] = [CreatureState() for _ in range(8)]
    for idx, creature in enumerate(creatures):
        creature.active = True
        creature.hp = 100.0
        creature.pos = Vec2(float(idx), float(idx) * 10.0)
        creature.flags = CreatureFlags(0)

    # Odd indices (1,3,5,7) are considered by the toggle:
    # - 1: eligible (should be deactivated)
    # - 3: ineligible due to flags bit 0x04
    # - 5: ineligible due to hp > 500
    # - 7: eligible (should be deactivated)
    creatures[3].flags = CreatureFlags(0x04)
    creatures[5].hp = 600.0

    perk_apply(state, [player], PerkId.LIFELINE_50_50, creatures=creatures)

    assert [entry.active for entry in creatures] == [True, False, True, True, True, True, True, False]

    effects_spawned = sum(1 for entry in state.effects.entries if entry.flags)
    assert effects_spawned == 8
    assert player.perk_counts[int(PerkId.LIFELINE_50_50)] == 1
