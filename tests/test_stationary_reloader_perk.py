from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_update
from crimson.perks import PerkId


def test_stationary_reloader_triples_reload_speed() -> None:
    state = GameplayState()

    base_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, weapon_id=0)
    base_player.reload_active = True
    base_player.reload_timer_max = 1.0
    base_player.reload_timer = 1.0

    perk_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, weapon_id=0)
    perk_player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1
    perk_player.reload_active = True
    perk_player.reload_timer_max = 1.0
    perk_player.reload_timer = 1.0

    player_update(base_player, PlayerInput(), dt=0.1, state=state)
    player_update(perk_player, PlayerInput(), dt=0.1, state=state)

    assert base_player.reload_timer == pytest.approx(0.9)
    assert perk_player.reload_timer == pytest.approx(0.7)
