from __future__ import annotations

from pathlib import Path

from crimson.persistence import save_status
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId


def test_weapon_assign_player_queues_reload_sfx_and_sets_aux_timer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())

    weapon_assign_player(player, WeaponId.SHOTGUN, state=state)

    assert player.weapon_reset_latch == 0
    assert player.aux_timer == 2.0
    assert state.sfx_queue == [SfxId.SHOTGUN_RELOAD]


def test_weapon_assign_player_skips_untracked_weapon_usage_ids() -> None:
    status = save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.default_status_data(),
        dirty=False,
    )
    state = GameplayState(status=status)
    player = PlayerState(index=0, pos=Vec2())

    weapon_assign_player(player, WeaponId.SHOTGUN, state=state)
    weapon_assign_player(player, WeaponId.NUKE_LAUNCHER, state=state)

    assert status.weapon_usage_count_for_weapon_id(WeaponId.SHOTGUN) == 1
    assert status.weapon_usage_count_for_weapon_id(WeaponId.NUKE_LAUNCHER) == 0
