"""1.9.8 rerolls a Fire Bullets pick while any player holds a flame or rocket weapon."""

from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.selection import bonus_pick_random_type
from crimson.cl_build import ClBuild
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_rng_progression

# `rand() % 162 + 1` = 125 picks Fire Bullets, 1 picks Points.
_FIRE_BULLETS_ROLL = 124
_POINTS_ROLL = 0


def _players(weapon_ids: tuple[WeaponId, WeaponId]) -> list[PlayerState]:
    # Player two is dead: native checks every player slot of the run.
    return [
        PlayerState(index=index, pos=Vec2(), health=health, weapon=WeaponSlot(weapon_id=weapon_id))
        for index, (weapon_id, health) in enumerate(zip(weapon_ids, (100.0, 0.0), strict=True))
    ]


@pytest.mark.parametrize(
    ("cl_build", "weapon_ids", "bonus_id", "draws"),
    [
        (ClBuild.V1_9_8, (WeaponId.FLAMETHROWER, WeaponId.PISTOL), BonusId.POINTS, 2),
        (ClBuild.V1_9_8, (WeaponId.PISTOL, WeaponId.ROCKET_MINIGUN), BonusId.POINTS, 2),
        (ClBuild.V1_9_8, (WeaponId.PISTOL, WeaponId.SHOTGUN), BonusId.FIRE_BULLETS, 1),
        (ClBuild.V1_9_93, (WeaponId.FLAMETHROWER, WeaponId.ROCKET_MINIGUN), BonusId.FIRE_BULLETS, 1),
    ],
    ids=["1.9.8-flamer", "1.9.8-dead-partner-rockets", "1.9.8-bullets", "1.9.93-flamer"],
)
def test_fire_bullets_reroll_draws_another_roll(
    cl_build: ClBuild, weapon_ids: tuple[WeaponId, WeaponId], bonus_id: BonusId, draws: int,
) -> None:
    rng = ScriptedCrand([_FIRE_BULLETS_ROLL, _POINTS_ROLL])
    state = GameplayState(rng=rng, cl_build=cl_build)

    assert bonus_pick_random_type(state.bonus_pool, state, _players(weapon_ids)) == bonus_id
    assert_rng_progression(rng, before_calls=0, before_state=0, expected_draws=draws)
