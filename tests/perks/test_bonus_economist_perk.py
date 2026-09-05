from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_bonus_economist_extends_bonus_timers() -> None:
    base_state = GameplayState()
    base_player = PlayerState(index=0, pos=Vec2())
    bonus_apply(base_state, base_player, BonusId.DOUBLE_EXPERIENCE, amount=10, origin=base_player.pos, creatures=[], players=[base_player])
    assert base_state.bonuses.double_experience == 6.0

    perk_state = GameplayState()
    perk_player = PlayerState(index=0, pos=Vec2())
    perk_player.perk_counts[int(PerkId.BONUS_ECONOMIST)] = 1
    bonus_apply(perk_state, perk_player, BonusId.DOUBLE_EXPERIENCE, amount=10, origin=perk_player.pos, creatures=[], players=[perk_player])
    assert perk_state.bonuses.double_experience == 9.0


@pytest.mark.parametrize(
    ("preserve_bugs", "perk_player_index", "expected_timer"),
    [
        (True, 0, 9.0),
        (True, 1, 6.0),
        (False, 1, 9.0),
    ],
    ids=["native-primary-owner", "native-secondary-owner", "corrected-secondary-owner"],
)
def test_bonus_economist_player_ownership(
    preserve_bugs: bool,
    perk_player_index: int,
    expected_timer: float,
) -> None:
    state = GameplayState(preserve_bugs=preserve_bugs)
    players = [
        PlayerState(index=0, pos=Vec2()),
        PlayerState(index=1, pos=Vec2()),
    ]
    players[perk_player_index].perk_counts[int(PerkId.BONUS_ECONOMIST)] = 1

    bonus_apply(
        state,
        players[1],
        BonusId.DOUBLE_EXPERIENCE,
        amount=10,
        origin=players[1].pos,
        creatures=[],
        players=players,
    )

    assert state.bonuses.double_experience == expected_timer
