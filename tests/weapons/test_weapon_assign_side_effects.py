from __future__ import annotations

from pathlib import Path

import pytest

from crimson.cl_build import ClBuild
from crimson.perks import PerkId
from crimson.perks.apply import perk_apply
from crimson.persistence import save_status
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapon_usage import weapon_usage_slot_for_weapon_id
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids


def test_weapon_assign_player_queues_reload_sfx_and_sets_weapon_popup_timer() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())

    weapon_assign_player(player, WeaponId.SHOTGUN, state=state)

    assert player.weapon_reset_latch == 0
    assert player.weapon_popup_timer == 2.0
    assert sfx_ids(state.sfx_queue) == [SfxId.SHOTGUN_RELOAD]


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

    shotgun_slot = weapon_usage_slot_for_weapon_id(WeaponId.SHOTGUN)
    assert shotgun_slot is not None
    assert weapon_usage_slot_for_weapon_id(WeaponId.NUKE_LAUNCHER) is None
    assert status.weapon_usage_count_slot(shotgun_slot) == 1
    assert sum(status.weapon_usage_counts) == 1


@pytest.mark.parametrize("preserve_bugs", [False, True])
@pytest.mark.parametrize("cl_build", list(ClBuild))
def test_my_favourite_weapon_clip_bonus_survives_a_reassign_except_with_1_9_8_bugs(cl_build, preserve_bugs) -> None:
    state = GameplayState(cl_build=cl_build, preserve_bugs=preserve_bugs)
    player = PlayerState(index=0, pos=Vec2())
    weapon_assign_player(player, WeaponId.PISTOL, state=state)

    perk_apply(state, [player], PerkId.MY_FAVOURITE_WEAPON)
    assert player.weapon.clip_size == WEAPON_BY_ID[WeaponId.PISTOL].clip_size + 2
    weapon_assign_player(player, WeaponId.SHOTGUN, state=state)

    # 1.9.8 adds the +2 only when the perk is picked (original bug 59).
    bonus = 0 if cl_build == ClBuild.V1_9_8 and preserve_bugs else 2
    assert player.weapon.clip_size == WEAPON_BY_ID[WeaponId.SHOTGUN].clip_size + bonus
    assert player.weapon.ammo == float(player.weapon.clip_size)
