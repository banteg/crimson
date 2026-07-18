from __future__ import annotations

import math

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.weapons import weapon_entry_for_projectile_type_id
from grim.geom import Vec2
from tests.support.factories import make_projectile_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


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
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )

    assert killed is False
    assert_float_close(creature.hp, 86.0)


def _step_pistol_projectile(
    *,
    barrel_greaser_player: int | None,
    preserve_bugs: bool = False,
) -> float:
    pool = ProjectilePool(size=1)
    travel_budget = float(weapon_entry_for_projectile_type_id(ProjectileTemplateId.PISTOL).travel_budget)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=travel_budget,
    )

    state = GameplayState(preserve_bugs=preserve_bugs)
    players = [PlayerState(index=0, pos=Vec2()), PlayerState(index=1, pos=Vec2())]
    if barrel_greaser_player is not None:
        players[barrel_greaser_player].perk_counts[int(PerkId.BARREL_GREASER)] = 1

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[],
            options=make_projectile_update_options(
                world_size=10000.0,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=state,
                players=players,
            ),
        ),
    )

    return float(pool.entries[0].pos.x)


def test_barrel_greaser_doubles_projectile_speed_steps() -> None:
    base_x = _step_pistol_projectile(barrel_greaser_player=None)
    greased_x = _step_pistol_projectile(barrel_greaser_player=0)
    # Movement is flushed from an accumulator in chunks, so doubling internal
    # step count does not map to an exact x2 world-space displacement.
    assert_float_close(base_x, 18.240001678466797)
    assert_float_close(greased_x, 35.519996643066406)
    assert greased_x > base_x


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_x"),
    [
        (True, 18.240001678466797),
        (False, 35.519996643066406),
    ],
)
def test_barrel_greaser_selects_native_player_zero_or_corrected_any_player(
    preserve_bugs: bool,
    expected_x: float,
) -> None:
    pos_x = _step_pistol_projectile(barrel_greaser_player=1, preserve_bugs=preserve_bugs)
    assert_float_close(pos_x, expected_x)
