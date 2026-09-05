from __future__ import annotations

from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_regression_bullets_fires_during_reload_and_costs_experience() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=1000)
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

    # int(1000 - f32(1.2) * 200): the native f32 reload time (1.2000000476...)
    # truncates the result to 759, not 760.
    assert player.experience == 759
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

    # int(1000 - f32(1.2) * 200): the native f32 reload time (1.2000000476...)
    # truncates the result to 759, not 760.
    assert player.experience == 759
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


def test_regression_bullets_fire_weapon_fires_during_manual_reload_and_spends_ammo() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), experience=1000)
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

    assert player.experience == 992  # int(1000 - (flamethrower.reload_time=2.0) * 4)
    assert any(entry.active for entry in state.particles.entries)
    assert_float_close(player.weapon.ammo, 4.9)
