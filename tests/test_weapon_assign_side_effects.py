from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, weapon_assign_player
from crimson.weapons import WeaponId


def test_weapon_assign_player_queues_reload_sfx_and_sets_aux_timer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)

    weapon_assign_player(player, int(WeaponId.SHOTGUN), state=state)

    assert player.weapon_reset_latch == 0
    assert player.aux_timer == 2.0
    assert state.sfx_queue == ["sfx_shotgun_reload"]
