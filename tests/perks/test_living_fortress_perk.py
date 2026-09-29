from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.perks import PerkId
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.factories import make_step_runtime, world_with_creature
from tests.support.helpers import assert_float_close


def test_living_fortress_scales_bullet_damage_by_stationary_timers() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)

    player0 = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.LIVING_FORTRESS] = 1
    player0.living_fortress_timer = 10.0  # 1.5x

    player1 = PlayerState(index=1, pos=Vec2())
    player1.living_fortress_timer = 20.0  # 2.0x

    world = world_with_creature(creature, rng=Crand(0x1234), perks=perks, players=[player0, player1])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 1, Vec2())

    assert killed is False
    assert_float_close(creature.hp, 70.0)
