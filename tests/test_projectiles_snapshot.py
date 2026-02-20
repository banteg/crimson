from __future__ import annotations

import math

from syrupy import SnapshotAssertion

from crimson.projectiles import ProjectilePool
from grim.geom import Vec2
from tests.factories import make_creature_state as _creature


def _fixed_rng(value: int):
    def _rng() -> int:
        return value

    return _rng


def test_projectile_pool_snapshot(snapshot: SnapshotAssertion) -> None:
    pool = ProjectilePool(size=2)
    idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=30.0,
    )
    creatures = [_creature(pos=Vec2(71.1428574, 0.0), hp=100.0)]
    hits = pool.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={4: 1.0},
        rng=_fixed_rng(2),
    )
    projectile = pool.entries[idx]

    snapshot.assert_match(
        {
            "hits": [
                {
                    "type_id": int(hit.type_id),
                    "origin": [round(float(hit.origin.x), 6), round(float(hit.origin.y), 6)],
                    "hit": [round(float(hit.hit.x), 6), round(float(hit.hit.y), 6)],
                    "target": [round(float(hit.target.x), 6), round(float(hit.target.y), 6)],
                }
                for hit in hits
            ],
            "projectile": {
                "active": bool(projectile.active),
                "life_timer": round(float(projectile.life_timer), 6),
                "pos": [round(float(projectile.pos.x), 6), round(float(projectile.pos.y), 6)],
                "damage_pool": round(float(projectile.damage_pool), 6),
            },
            "creature_hp": round(float(creatures[0].hp), 6),
        },
    )
