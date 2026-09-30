from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.availability import build_perk_availability, perk_can_offer
from crimson.persistence.save_status import GameStatusData
from crimson.sim.gameplay_state import GameplayState


def test_antiperk_is_excluded_by_availability_not_offer_predicate() -> None:
    state = GameplayState()
    assert perk_can_offer(state, PerkId.ANTIPERK, game_mode=GameMode.SURVIVAL, player_count=1)
    assert not build_perk_availability(status=GameStatusData())[int(PerkId.ANTIPERK)]
