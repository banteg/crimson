from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState, PlayerState, player_start_reload
from crimson.perks import PerkId
from crimson.projectiles import ProjectileTypeId
from crimson.weapons import WEAPON_BY_ID


def test_fastloader_scales_reload_timer() -> None:
    weapon_id = int(ProjectileTypeId.ASSAULT_RIFLE)
    reload_time = float(WEAPON_BY_ID[weapon_id].reload_time or 0.0)
    assert reload_time > 0.0

    base = PlayerState(index=0, pos_x=0.0, pos_y=0.0, weapon_id=weapon_id)
    perk = PlayerState(index=0, pos_x=0.0, pos_y=0.0, weapon_id=weapon_id)
    perk.perk_counts[int(PerkId.FASTLOADER)] = 1

    base_state = GameplayState()
    perk_state = GameplayState()

    player_start_reload(base, base_state)
    player_start_reload(perk, perk_state)

    assert base.reload_active is True
    assert perk.reload_active is True
    assert base.reload_timer == pytest.approx(reload_time)
    assert perk.reload_timer == pytest.approx(reload_time * 0.7)
    assert perk.reload_timer_max == pytest.approx(perk.reload_timer)
