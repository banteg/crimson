from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_projectile_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_ion_gun_master_increases_ion_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=7,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.hp, 88.0)


def test_ion_gun_master_increases_ion_aoe_radius() -> None:
    def _step(*, perk_active: bool) -> float:
        pool = ProjectilePool(size=1)
        proj_idx = pool.spawn(
            pos=Vec2(),
            angle=0.0,
            type_id=ProjectileTemplateId.ION_RIFLE,
            owner=OwnerRef.from_local_player(0),
            travel_budget=45.0,
        )
        pool.entries[proj_idx].life_timer = 0.39

        creature = CreatureState(active=True, hp=10.0, pos=Vec2(105.0, 0.0), size=50.0)
        players = [PlayerState(index=0, pos=Vec2())]
        if perk_active:
            players[0].perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

        pool.step(
            PrimaryStepCtx(
                dt=0.016,
                creatures=[creature],
                options=make_projectile_update_options(
                    world_size=10000.0,
                    rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                    players=players,
                ),
            ),
        )

        return float(creature.hp)

    assert_float_close(_step(perk_active=False), 10.0)
    assert _step(perk_active=True) < 10.0
