from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_ammunition_within_fires_during_reload_and_costs_health() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = 0  # pistol
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert player.health == pytest.approx(9.0)
    assert player.experience == 1
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.ammo == 0


def test_ammunition_within_blocks_fire_when_experience_is_zero() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, health=10.0, experience=0)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = 0
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert player.health == pytest.approx(10.0)
    assert not any(entry.active for entry in state.projectiles.entries)


def test_ammunition_within_fire_ammo_class_costs_less_health() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, health=10.0, experience=1)
    player.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player.weapon_id = 7  # flamethrower
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert player.health == pytest.approx(9.85)
    assert any(entry.active for entry in state.projectiles.entries)
