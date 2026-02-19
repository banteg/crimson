from __future__ import annotations

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import MockCrand


def test_pyromaniac_increases_fire_damage_and_consumes_rng() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROMANIAC)] = 1

    rand = MockCrand(0)
    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=4,
        impulse=Vec2(),
        owner_id=-100,
        dt=0.016,
        players=[player],
        rand=rand,
    )

    assert killed is False
    assert creature.hp == pytest.approx(85.0)
    assert rand.calls == 1
