from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_plaguebearer_apply_sets_active_flag_for_all_players() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2())
    other = PlayerState(index=1, pos=Vec2())

    perk_apply(state, [owner, other], PerkId.PLAGUEBEARER)

    assert owner.plaguebearer_active
    assert other.plaguebearer_active


def test_plaguebearer_preserve_bugs_sets_only_player_zero_active() -> None:
    state = GameplayState()
    state.preserve_bugs = True
    owner = PlayerState(index=0, pos=Vec2())
    other = PlayerState(index=1, pos=Vec2())

    perk_apply(state, [owner, other], PerkId.PLAGUEBEARER)

    assert owner.plaguebearer_active
    assert not other.plaguebearer_active
