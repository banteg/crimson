from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import player_fire_weapon
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close


def test_ammunition_within_fires_during_reload_and_costs_health() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = int(WeaponId.PISTOL)
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True), 0.016, state)

    assert_float_close(player.health, 9.0)
    assert player.experience == 1
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.ammo == -1


def test_ammunition_within_fires_during_manual_reload_when_ammo_remaining() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = int(WeaponId.PISTOL)
    player.ammo = 5
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True), 0.016, state)

    assert_float_close(player.health, 9.0)
    assert player.experience == 1
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.ammo == 4


def test_ammunition_within_blocks_fire_when_experience_is_zero() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=0)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = int(WeaponId.PISTOL)
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True), 0.016, state)

    assert_float_close(player.health, 10.0)
    assert not any(entry.active for entry in state.projectiles.entries)


def test_ammunition_within_fire_ammo_class_costs_less_health() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = int(WeaponId.FLAMETHROWER)
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True), 0.016, state)

    assert_float_close(player.health, f32(9.85))
    assert any(entry.active for entry in state.particles.entries)


def test_ammunition_within_fire_weapon_fires_during_manual_reload_and_spends_ammo() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2(), health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = int(WeaponId.FLAMETHROWER)
    player.ammo = 5
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim=Vec2(10.0, 0.0), fire_down=True), 0.016, state)

    assert_float_close(player.health, f32(9.85))
    assert any(entry.active for entry in state.particles.entries)
    assert_float_close(player.ammo, 4.9)
