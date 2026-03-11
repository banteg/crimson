from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_pyromaniac_increases_fire_damage_and_consumes_rng() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROMANIAC)] = 1

    rand = ScriptedCrand(0)
    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=4,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        rng=rand,
    )

    assert killed is False
    assert_float_close(creature.hp, 85.0)
    assert rand.calls == 1
    assert [record.caller for record in rand.records_since()] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_PYROMANIAC,
    ]
