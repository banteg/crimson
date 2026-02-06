from __future__ import annotations

from grim.geom import Vec2

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_perk_apply_lifeline_50_50_deactivates_every_other_eligible_creature_slot() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))

    creatures = [CreatureState() for _ in range(8)]
    for idx, creature in enumerate(creatures):
        creature.active = True
        creature.hp = 100.0
        creature.x = float(idx)
        creature.y = float(idx) * 10.0
        creature.flags = 0

    # Odd indices (1,3,5,7) are considered by the toggle:
    # - 1: eligible (should be deactivated)
    # - 3: ineligible due to flags bit 0x04
    # - 5: ineligible due to hp > 500
    # - 7: eligible (should be deactivated)
    creatures[3].flags = 0x04
    creatures[5].hp = 600.0

    perk_apply(state, [player], PerkId.LIFELINE_50_50, creatures=creatures)

    assert [entry.active for entry in creatures] == [True, False, True, True, True, True, True, False]

    effects_spawned = sum(1 for entry in state.effects.entries if entry.flags)
    assert effects_spawned == 8
    assert player.perk_counts[int(PerkId.LIFELINE_50_50)] == 1

