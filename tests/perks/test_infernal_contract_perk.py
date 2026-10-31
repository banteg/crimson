from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.perks.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


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


@pytest.mark.parametrize(
    ("cl_build", "preserve_bugs", "expected_health"),
    [
        (ClBuild.V1_9_8, True, (f32(0.1), 80.0)),
        (ClBuild.V1_9_8, False, (-5.0, f32(0.1))),
        (ClBuild.V1_9_93, True, (-5.0, f32(0.1))),
    ],
)
def test_infernal_contract_1_9_8_revives_player_one_and_spares_player_two(
    cl_build: ClBuild, preserve_bugs: bool, expected_health: tuple[float, float],
) -> None:
    # 1.9.8 writes player one's health unchecked and skips player two (original bug 58); the default
    # plays 1.9.93's checked write for both.
    state = GameplayState(cl_build=cl_build, preserve_bugs=preserve_bugs)
    players = [
        PlayerState(index=0, pos=Vec2(), health=-5.0),
        PlayerState(index=1, pos=Vec2(), health=80.0),
    ]

    perk_apply(state, players, PerkId.INFERNAL_CONTRACT)

    assert (players[0].health, players[1].health) == expected_health
    assert players[0].level == 4
    assert state.perk_selection.pending_count == 3
