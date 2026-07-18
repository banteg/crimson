from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_infernal_contract_grants_levels_and_sets_low_health() -> None:
    state = GameplayState()
    perk_state = PerkSelectionState()

    owner = PlayerState(index=0, pos=Vec2(), level=5, health=100.0)
    other = PlayerState(index=1, pos=Vec2(), level=1, health=100.0)

    perk_apply(state, [owner, other], PerkId.INFERNAL_CONTRACT, perk_state=perk_state)

    assert owner.level == 8
    assert perk_state.pending_count == 3
    assert perk_state.choices_dirty is True
    assert owner.health == f32(0.1)
    assert other.health == f32(0.1)


def test_infernal_contract_player_scope_follows_bug_mode() -> None:
    for preserve_bugs, expected_health in (
        (True, (f32(0.1), f32(0.1), 60.0)),
        (False, (f32(0.1), f32(0.1), f32(0.1))),
    ):
        state = GameplayState(preserve_bugs=preserve_bugs)
        players = [
            PlayerState(index=0, pos=Vec2(), health=100.0),
            PlayerState(index=1, pos=Vec2(), health=80.0),
            PlayerState(index=2, pos=Vec2(), health=60.0),
        ]

        perk_apply(state, players, PerkId.INFERNAL_CONTRACT)

        assert tuple(player.health for player in players) == expected_health
