from __future__ import annotations

import math

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.perks import PerkId
from crimson.projectiles.runtime import PrimaryStepCtx
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, world_with_creature
from tests.support.helpers import assert_float_close


def test_barrel_greaser_increases_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.BARREL_GREASER] = 1

    world = world_with_creature(creature, rng=Crand(0x1234), perks=perks, players=[player])
    killed = creature_apply_damage(make_step_runtime(world, dt=0.016), 0, 10.0, 1, Vec2(), OWNER_LOCAL_PLAYER)

    assert killed is False
    assert_float_close(creature.hp, 86.0)


def _step_pistol_projectile(*, barrel_greaser: bool) -> float:
    world = make_world()
    world.state.perks[int(PerkId.BARREL_GREASER)] = int(barrel_greaser)
    pool = world.state.projectiles
    proj_idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
    )

    pool.step(
        PrimaryStepCtx(step_runtime=make_step_runtime(world, dt=0.016), dt=0.016),
    )

    return float(pool.entries[proj_idx].pos.x)


def test_barrel_greaser_doubles_projectile_speed_steps() -> None:
    base_x = _step_pistol_projectile(barrel_greaser=False)
    greased_x = _step_pistol_projectile(barrel_greaser=True)
    # Movement is flushed from an accumulator in chunks, so doubling internal
    # step count does not map to an exact x2 world-space displacement.
    assert_float_close(base_x, 18.240001678466797)
    assert_float_close(greased_x, 35.519996643066406)
    assert greased_x > base_x
