from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, weapon_assign_player


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_rocket_minigun_fires_full_clip_secondary_projectiles() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, 17)
    assert player.ammo == player.clip_size

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)

    spawned = [entry for entry in state.secondary_projectiles.entries if entry.active]
    assert len(spawned) == player.clip_size
    assert player.ammo == 0
    assert player.reload_active is True

    assert state.weapon_shots_fired[0][17] == player.clip_size

    shot_angle = math.pi / 2.0
    step = float(player.clip_size) * (math.pi / 3.0)
    expected0 = (shot_angle - math.pi) - step * float(player.clip_size) * 0.5
    assert math.isclose(spawned[0].angle, expected0, abs_tol=1e-9)

