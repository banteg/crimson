from __future__ import annotations

import math

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.gameplay import PlayerState
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId
from crimson.weapons import WEAPON_BY_ID


def test_barrel_greaser_increases_bullet_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.perk_counts[int(PerkId.BARREL_GREASER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse_x=0.0,
        impulse_y=0.0,
        owner_id=-100,
        dt=0.016,
        players=[player],
        rand=lambda: 0,
    )

    assert killed is False
    assert creature.hp == pytest.approx(86.0)


def _step_pistol_projectile(*, barrel_greaser_active: bool) -> float:
    pool = ProjectilePool(size=1)
    meta = WEAPON_BY_ID[int(ProjectileTypeId.PISTOL)].projectile_meta
    base_damage = float(meta if meta is not None else 45.0)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=ProjectileTypeId.PISTOL,
        owner_id=-100,
        base_damage=base_damage,
    )

    players = [PlayerState(index=0, pos_x=0.0, pos_y=0.0)]
    if barrel_greaser_active:
        players[0].perk_counts[int(PerkId.BARREL_GREASER)] = 1

    pool.update(
        0.016,
        [],
        world_size=10000.0,
        rng=lambda: 0,
        players=players,
    )

    return float(pool.entries[0].pos_x)


def test_barrel_greaser_doubles_projectile_speed_steps() -> None:
    base_x = _step_pistol_projectile(barrel_greaser_active=False)
    greased_x = _step_pistol_projectile(barrel_greaser_active=True)
    assert greased_x == pytest.approx(base_x * 2.0, rel=0.05)
