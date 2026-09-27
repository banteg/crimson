from __future__ import annotations

import math

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from tests.support.factories import make_projectile_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_barrel_greaser_increases_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.BARREL_GREASER] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        perks=perks,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.hp, 86.0)


def _step_pistol_projectile(*, barrel_greaser: bool) -> float:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
    )

    state = GameplayState()
    state.perks[int(PerkId.BARREL_GREASER)] = int(barrel_greaser)

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[],
            options=make_projectile_update_options(
                creatures=[],
                world_size=10000.0,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=state,
                players=[PlayerState(index=0, pos=Vec2())],
            ),
        ),
    )

    return float(pool.entries[0].pos.x)


def test_barrel_greaser_doubles_projectile_speed_steps() -> None:
    base_x = _step_pistol_projectile(barrel_greaser=False)
    greased_x = _step_pistol_projectile(barrel_greaser=True)
    # Movement is flushed from an accumulator in chunks, so doubling internal
    # step count does not map to an exact x2 world-space displacement.
    assert_float_close(base_x, 18.240001678466797)
    assert_float_close(greased_x, 35.519996643066406)
    assert greased_x > base_x
