from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon
from crimson.perks import PerkId


def _fire_once(state: GameplayState, player: PlayerState) -> float:
    player_fire_weapon(player, PlayerInput(fire_down=True), dt=0.1, state=state)
    return float(player.shot_cooldown)


def test_fastshot_scales_shot_cooldown() -> None:
    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), weapon_id=1, ammo=2)
    base_cd = _fire_once(base_state, base_player)

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), weapon_id=1, ammo=2)
    perk_player.perk_counts[int(PerkId.FASTSHOT)] = 1
    perk_cd = _fire_once(perk_state, perk_player)

    assert perk_cd == pytest.approx(base_cd * 0.88)
