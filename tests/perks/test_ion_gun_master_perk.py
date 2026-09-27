from __future__ import annotations

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
        pool = ProjectilePool(size=1)
        proj_idx = pool.spawn(
            pos=Vec2(),
            angle=0.0,
            type_id=ProjectileTemplateId.ION_RIFLE,
            owner=OwnerRef.from_local_player(0),
        )
        pool.entries[proj_idx].life_timer = 0.39

        creature = CreatureState(active=True, hp=10.0, pos=Vec2(105.0, 0.0), size=50.0)
        state = GameplayState()
        state.perks[int(PerkId.ION_GUN_MASTER)] = int(ion_gun_master)

        pool.step(
            PrimaryStepCtx(
                dt=0.016,
                creatures=[creature],
                options=make_projectile_update_options(
                    creatures=[creature],
                    rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                    runtime_state=state,
                    players=[PlayerState(index=0, pos=Vec2())],
                ),
            ),
        )

        return float(creature.hp)

    assert_float_close(_step(ion_gun_master=False), 10.0)
    assert _step(ion_gun_master=True) < 10.0
