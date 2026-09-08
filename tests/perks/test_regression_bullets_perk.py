from __future__ import annotations

import pytest

from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


@pytest.mark.parametrize(
    ("experience", "remaining"),
    [(1000, 760), (16_777_217, 16_776_977), (16_777_219, 16_776_979)],
)
def test_regression_bullets_fires_during_reload_and_costs_experience(experience: int, remaining: int) -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=experience)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon.weapon_id = WeaponId.PISTOL
    player.weapon.ammo = 0
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.5

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True),
            dt=0.016,
            state=state,
        ),
    )

    # Native FMUL then FSUBP round at PC=24: 240.000015... then 760.0,
    # before _ftol truncates. Host double arithmetic incorrectly gives 759.
    # FILD preserves integer XP exactly until the subtraction, even above 2**24.
    assert player.experience == remaining
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.weapon.ammo == -1


def test_regression_bullets_fires_during_manual_reload_when_ammo_remaining() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=1000)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon.weapon_id = WeaponId.PISTOL
    player.weapon.ammo = 5
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.5

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True),
            dt=0.016,
            state=state,
        ),
    )

    # The PC=24 subtraction rounds to 760.0 before the truncating conversion.
    assert player.experience == 760
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.weapon.ammo == 4


def test_regression_bullets_blocks_fire_when_experience_is_zero() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=0)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon.weapon_id = WeaponId.PISTOL
    player.weapon.ammo = 0
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.5

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True),
            dt=0.016,
            state=state,
        ),
    )

    assert not any(entry.active for entry in state.projectiles.entries)


@pytest.mark.parametrize(("experience", "remaining"), [(1000, 992), (2_147_483_647, 0)])
def test_regression_bullets_fire_weapon_fires_during_manual_reload_and_spends_ammo(
    experience: int,
    remaining: int,
) -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=experience)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon.weapon_id = WeaponId.FLAMETHROWER
    player.weapon.ammo = 5
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.5

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True),
            dt=0.016,
            state=state,
        ),
    )

    # Cost is 2.0*4. At INT32_MAX, PC24 rounds to 2**31; EAX is negative and clamps to zero.
    assert player.experience == remaining
    assert any(entry.active for entry in state.particles.entries)
    assert_float_close(player.weapon.ammo, 4.9)
