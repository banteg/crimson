from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_ammunition_within_fires_during_reload_and_costs_health() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
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

    assert_float_close(player.health, 9.0)
    assert player.experience == 1
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.weapon.ammo == -1


def test_ammunition_within_fires_during_manual_reload_when_ammo_remaining() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
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

    assert_float_close(player.health, 9.0)
    assert player.experience == 1
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.weapon.ammo == 4


def test_ammunition_within_blocks_fire_when_experience_is_zero() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=0)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
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

    assert_float_close(player.health, 10.0)
    assert not any(entry.active for entry in state.projectiles.entries)


def test_ammunition_within_fire_ammo_class_costs_less_health() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon.weapon_id = WeaponId.FLAMETHROWER
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

    assert_float_close(player.health, f32(9.85))
    assert any(entry.active for entry in state.particles.entries)


def test_ammunition_within_fire_weapon_fires_during_manual_reload_and_spends_ammo() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
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

    assert_float_close(player.health, f32(9.85))
    assert any(entry.active for entry in state.particles.entries)
    assert_float_close(player.weapon.ammo, 4.9)
