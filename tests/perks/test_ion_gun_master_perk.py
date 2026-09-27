from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.math_parity import f32
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.runtime import PrimaryStepCtx
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, make_projectile_update_options, place_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_ion_gun_master_increases_ion_damage() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0)
    player = PlayerState(index=0, pos=Vec2())
    perks = PerkCounts()
    perks[PerkId.ION_GUN_MASTER] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=7,
        impulse=Vec2(),
        owner=OwnerRef.from_local_player(0),
        dt=0.016,
        players=[player],
        perks=perks,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.hp, 88.0)


def test_ion_gun_master_increases_ion_aoe_radius() -> None:
    def _step(*, ion_gun_master: bool) -> float:
        world = make_world()
        world.state.perks[int(PerkId.ION_GUN_MASTER)] = int(ion_gun_master)
        creatures = place_creatures(world, [make_creature_state(pos=Vec2(105.0, 0.0), hp=10.0)])
        pool = world.state.projectiles
        proj_idx = pool.spawn(
            pos=Vec2(),
            angle=0.0,
            type_id=ProjectileTemplateId.ION_RIFLE,
            owner=OwnerRef.from_local_player(0),
        )
        pool.entries[proj_idx].life_timer = 0.39

        pool.step(
            PrimaryStepCtx(
                dt=0.016,
                creatures=creatures,
                options=make_projectile_update_options(world),
            ),
        )

        return float(creatures[0].hp)

    assert_float_close(_step(ion_gun_master=False), 10.0)
    # Linger AoE deals 100 dps ion damage, scaled x1.2 by the perk: 10 - 0.016 * 100 * 1.2.
    assert_float_close(_step(ion_gun_master=True), f32(8.08))
