from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import assert_float_close


def test_uranium_filled_bullets_doubles_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.URANIUM_FILLED_BULLETS] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        perks=perks,
        rng=Crand(0x1234),
    )

    assert killed is False
    assert_float_close(creature.hp, 80.0)
