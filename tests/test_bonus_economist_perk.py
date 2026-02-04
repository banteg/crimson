from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.gameplay import GameplayState, PlayerState, bonus_apply
from crimson.perks import PerkId


def test_bonus_economist_extends_bonus_timers() -> None:
    base_state = GameplayState()
    base_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    bonus_apply(base_state, base_player, BonusId.DOUBLE_EXPERIENCE, amount=10)
    assert base_state.bonuses.double_experience == 6.0

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    perk_player.perk_counts[int(PerkId.BONUS_ECONOMIST)] = 1
    bonus_apply(perk_state, perk_player, BonusId.DOUBLE_EXPERIENCE, amount=10)
    assert perk_state.bonuses.double_experience == 9.0
