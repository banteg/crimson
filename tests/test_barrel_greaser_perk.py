from __future__ import annotations

import math

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId, ProjectileUpdateOptions
from crimson.sim.state_types import PlayerState
from crimson.weapons import WEAPON_BY_ID
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_barrel_greaser_increases_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.BARREL_GREASER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        rand=lambda: 0,
    )

    assert killed is False
    assert_float_close(creature.hp, 86.0)


def _step_pistol_projectile(*, barrel_greaser_active: bool) -> float:
    pool = ProjectilePool(size=1)
    meta = WEAPON_BY_ID[int(ProjectileTypeId.PISTOL)].travel_budget
    travel_budget = float(meta if meta is not None else 45.0)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTypeId.PISTOL,
        owner_id=OwnerRef.from_local_player(0),
        travel_budget=travel_budget,
    )

    players = [PlayerState(index=0, pos=Vec2())]
    if barrel_greaser_active:
        players[0].perk_counts[int(PerkId.BARREL_GREASER)] = 1

    pool.update(
        0.016,
        [],
        options=ProjectileUpdateOptions(
            world_size=10000.0,
            rng=lambda: 0,
            players=players,
        ),
    )

    return float(pool.entries[0].pos.x)


def test_barrel_greaser_doubles_projectile_speed_steps() -> None:
    base_x = _step_pistol_projectile(barrel_greaser_active=False)
    greased_x = _step_pistol_projectile(barrel_greaser_active=True)
    # Movement is flushed from an accumulator in chunks, so doubling internal
    # step count does not map to an exact x2 world-space displacement.
    assert_float_close(base_x, 18.240001678466797)
    assert_float_close(greased_x, 35.519996643066406)
    assert greased_x > base_x
