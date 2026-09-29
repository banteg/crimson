from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import make_step_runtime, world_with_creature
from tests.support.helpers import assert_float_close


def test_pyromaniac_increases_fire_damage_and_consumes_rng() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.PYROMANIAC] = 1

    rand = RecordingCrand(Crand(0x1234))
    world = world_with_creature(creature, rng=rand, perks=perks, players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 4, Vec2())

    assert killed is False
    assert_float_close(creature.hp, 85.0)
    assert rand.calls == 1
    assert [record.caller for record in rand.records_since()] == [
        RngCallerStatic.CREATURE_APPLY_DAMAGE_PYROMANIAC,
    ]
