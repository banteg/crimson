from __future__ import annotations

from crimson.gameplay import survival_check_level_up
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_survival_level_up_advances_one_threshold_per_tick() -> None:
    player = PlayerState(index=0, pos=Vec2(), level=1, experience=5000)
    perk_state = PerkSelectionState()

    advanced = survival_check_level_up(player, perk_state)

    assert advanced == 1
    assert player.level == 2
    assert perk_state.pending_count == 1
    assert perk_state.choices_dirty is True

    advanced = survival_check_level_up(player, perk_state)

    assert advanced == 1
    assert player.level == 3
    assert perk_state.pending_count == 2

