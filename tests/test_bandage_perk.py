from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_bandage_clamps_health_and_spawns_burst() -> None:
    state = GameplayState()
    state.rng = _FixedRng(49)  # (rand % 50) + 1 == 50

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=3.0)
    perk_apply(state, [player], PerkId.BANDAGE)

    assert player.health == 100.0
    assert len(state.effects.iter_active()) == 8
