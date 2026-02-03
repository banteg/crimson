from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_regression_bullets_fires_during_reload_and_costs_experience() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, experience=1000)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon_id = 1  # pistol
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert player.experience == 760  # int(1000 - (pistol.reload_time=1.2) * 200)
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.ammo == 0


def test_regression_bullets_fires_during_manual_reload_when_ammo_remaining() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, experience=1000)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon_id = 1  # pistol
    player.ammo = 5
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert player.experience == 760  # int(1000 - (pistol.reload_time=1.2) * 200)
    assert any(entry.active for entry in state.projectiles.entries)
    assert player.ammo == 5


def test_regression_bullets_blocks_fire_when_experience_is_zero() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, experience=0)
    player.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
    player.weapon_id = 1
    player.ammo = 0
    player.reload_active = True
    player.reload_timer = 0.5

    player_fire_weapon(player, PlayerInput(aim_x=10.0, aim_y=0.0, fire_down=True), 0.016, state)

    assert not any(entry.active for entry in state.projectiles.entries)
