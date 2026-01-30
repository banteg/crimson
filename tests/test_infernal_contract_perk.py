from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.gameplay import PerkSelectionState
from crimson.perks import PerkId


def test_infernal_contract_grants_levels_and_sets_low_health() -> None:
    state = GameplayState()
    perk_state = PerkSelectionState()

    owner = PlayerState(index=0, pos_x=0.0, pos_y=0.0, level=5, health=100.0)
    other = PlayerState(index=1, pos_x=0.0, pos_y=0.0, level=1, health=100.0)

    perk_apply(state, [owner, other], PerkId.INFERNAL_CONTRACT, perk_state=perk_state)

    assert owner.level == 8
    assert perk_state.pending_count == 3
    assert perk_state.choices_dirty is True
    assert owner.health == 0.1
    assert other.health == 0.1
