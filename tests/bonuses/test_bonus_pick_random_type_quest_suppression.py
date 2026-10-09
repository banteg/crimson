from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.selection import bonus_pick_random_type
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


@pytest.mark.parametrize(
    ("rng_values", "hardcore", "quest_stage_major", "quest_stage_minor", "expected_bonus_id"),
    [
        ([34, 94, 0], True, 2, 10, BonusId.POINTS),
        ([34, 94], True, 3, 10, BonusId.FREEZE),
    ],
    ids=[
        "hardcore-quest-2-10-suppresses-nuke-and-freeze",
        "hardcore-quest-3-10-suppresses-nuke",
    ],
)
def test_bonus_pick_random_type_quest_suppression(
    rng_values: list[int],
    hardcore: bool,
    quest_stage_major: int,
    quest_stage_minor: int,
    expected_bonus_id: BonusId,
) -> None:
    state = GameplayState(rng=ScriptedCrand(rng_values, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    state.game_mode = GameMode.QUESTS
    state.hardcore = hardcore
    state.quest_level = QuestLevel(quest_stage_major, quest_stage_minor)
    players = [PlayerState(index=0, pos=Vec2())]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == expected_bonus_id


def test_bonus_pick_random_type_only_checks_two_native_shield_slots() -> None:
    state = GameplayState(rng=ScriptedCrand([84]))
    players = [
        PlayerState(index=0, pos=Vec2()),
        PlayerState(index=1, pos=Vec2()),
        PlayerState(index=2, pos=Vec2(), shield_timer=1.0),
    ]

    assert bonus_pick_random_type(state.bonus_pool, state, players) == BonusId.SHIELD
