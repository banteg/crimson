from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update
from crimson.perks import PerkId


def test_anxious_loader_reduces_reload_timer_on_fire_press() -> None:
    state = GameplayState()

    base_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), weapon_id=1)
    base_player.reload_active = True
    base_player.reload_timer_max = 1.0
    base_player.reload_timer = 1.0

    perk_player = PlayerState(index=0, pos=Vec2(0.0, 0.0), weapon_id=1)
    perk_player.perk_counts[int(PerkId.ANXIOUS_LOADER)] = 1
    perk_player.reload_active = True
    perk_player.reload_timer_max = 1.0
    perk_player.reload_timer = 1.0

    input_state = PlayerInput(fire_pressed=True)
    player_update(base_player, input_state, dt=0.1, state=state)
    player_update(perk_player, input_state, dt=0.1, state=state)

    assert base_player.reload_timer == pytest.approx(0.9)
    assert perk_player.reload_timer == pytest.approx(0.85)
