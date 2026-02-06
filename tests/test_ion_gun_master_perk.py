from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.gameplay import PlayerState
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId


def test_ion_gun_master_increases_ion_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=7,
        impulse=Vec2(),
        owner_id=-100,
        dt=0.016,
        players=[player],
        rand=lambda: 0,
    )

    assert killed is False
    assert creature.hp == pytest.approx(88.0)


def test_ion_gun_master_increases_ion_aoe_radius() -> None:
    def _step(*, perk_active: bool) -> float:
        pool = ProjectilePool(size=1)
        proj_idx = pool.spawn(
            pos=Vec2(0.0, 0.0),
            angle=0.0,
            type_id=ProjectileTypeId.ION_RIFLE,
            owner_id=-100,
            base_damage=45.0,
        )
        pool.entries[proj_idx].life_timer = 0.39

        creature = CreatureState(active=True, hp=10.0, pos=Vec2(105.0, 0.0), size=50.0)
        players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]
        if perk_active:
            players[0].perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

        pool.update(
            0.016,
            [creature],
            world_size=10000.0,
            rng=lambda: 0,
            players=players,
        )

        return float(creature.hp)

    assert _step(perk_active=False) == pytest.approx(10.0)
    assert _step(perk_active=True) < 10.0
