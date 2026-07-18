from __future__ import annotations

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState
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
    def _step(*, perk_player: int | None, preserve_bugs: bool = False) -> float:
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
        state = GameplayState(preserve_bugs=preserve_bugs)
        players = [PlayerState(index=0, pos=Vec2()), PlayerState(index=1, pos=Vec2())]
        if perk_player is not None:
            players[perk_player].perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

        pool.step(
            PrimaryStepCtx(
                dt=0.016,
                creatures=[creature],
                options=make_projectile_update_options(
                    world_size=10000.0,
                    rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                    runtime_state=state,
                    players=players,
                ),
            ),
        )

        return float(creature.hp)

    assert_float_close(_step(perk_player=None), 10.0)
    assert _step(perk_player=0) < 10.0


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_damage"),
    [
        (True, False),
        (False, True),
    ],
)
def test_ion_gun_master_selects_native_player_zero_or_corrected_any_player(
    preserve_bugs: bool,
    expected_damage: bool,
) -> None:
    pool = ProjectilePool(size=1)
    proj_idx = pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.ION_RIFLE,
        owner=OwnerRef.from_local_player(1),
        travel_budget=45.0,
    )
    pool.entries[proj_idx].life_timer = 0.39

    creature = CreatureState(active=True, hp=10.0, pos=Vec2(105.0, 0.0), size=50.0)
    state = GameplayState(preserve_bugs=preserve_bugs)
    players = [PlayerState(index=0, pos=Vec2()), PlayerState(index=1, pos=Vec2())]
    players[1].perk_counts[int(PerkId.ION_GUN_MASTER)] = 1

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=10000.0,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=state,
                players=players,
            ),
        ),
    )

    assert (creature.hp < 10.0) is expected_damage
