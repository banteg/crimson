from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.gameplay import BonusPool, GameplayState, PlayerState, bonus_telekinetic_update
from crimson.perks import PerkId


def test_telekinetic_picks_up_bonus_after_hover_time() -> None:
    state = GameplayState()
    state.bonus_pool = BonusPool()
    entry = state.bonus_pool.spawn_at(100.0, 100.0, BonusId.POINTS)
    assert entry is not None

    base_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, aim_x=100.0, aim_y=100.0)
    assert bonus_telekinetic_update(state, [base_player], dt=0.7) == []
    assert entry.picked is False

    perk_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0, aim_x=100.0, aim_y=100.0)
    perk_player.perk_counts[int(PerkId.TELEKINETIC)] = 1
    pickups = bonus_telekinetic_update(state, [perk_player], dt=0.7)

    assert len(pickups) == 1
    assert entry.picked is True
    assert perk_player.experience == 500
