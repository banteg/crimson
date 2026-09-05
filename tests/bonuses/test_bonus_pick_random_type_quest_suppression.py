from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.selection import bonus_pick_random_type
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.quests.level import QuestLevel
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


@pytest.mark.parametrize(
    ("rng_values", "hardcore", "quest_stage_major", "quest_stage_minor", "expected_bonus_id"),
    [
        ([34, 94], False, 2, 10, BonusId.FREEZE),
        ([34, 94, 0], True, 2, 10, BonusId.POINTS),
        ([34, 94, 0], False, 4, 10, BonusId.POINTS),
        ([34, 94], False, 5, 10, BonusId.FREEZE),
        ([34, 94], True, 3, 10, BonusId.FREEZE),
    ],
    ids=[
        "quest-2-10-suppresses-nuke",
        "hardcore-quest-2-10-suppresses-nuke-and-freeze",
        "quest-4-10-suppresses-nuke-and-freeze",
        "quest-5-10-suppresses-nuke",
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


def test_bonus_pick_random_type_tags_exact_native_callers() -> None:
    rng = ScriptedCrand([13, 0])
    state = GameplayState(rng=rng)
    players = [PlayerState(index=0, pos=Vec2())]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)

    assert bonus_id == BonusId.ENERGIZER
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.BONUS_PICK_RANDOM_TYPE_ROLL,
        RngCallerStatic.BONUS_PICK_RANDOM_TYPE_ENERGIZER,
    ]


@pytest.mark.parametrize(
    ("rng_values", "perk_id", "expected_bonus_id"),
    [
        ([13, 1], PerkId.MY_FAVOURITE_WEAPON, BonusId.WEAPON),
        ([104], PerkId.DEATH_CLOCK, BonusId.MEDIKIT),
    ],
)
def test_bonus_pick_random_type_only_checks_primary_player_perks(
    rng_values: list[int],
    perk_id: PerkId,
    expected_bonus_id: BonusId,
) -> None:
    state = GameplayState(rng=ScriptedCrand(rng_values))
    players = [PlayerState(index=0, pos=Vec2()), PlayerState(index=1, pos=Vec2())]
    players[1].perk_counts[int(perk_id)] = 1

    assert bonus_pick_random_type(state.bonus_pool, state, players) == expected_bonus_id


def test_bonus_pick_random_type_only_checks_two_native_shield_slots() -> None:
    state = GameplayState(rng=ScriptedCrand([84]))
    players = [
        PlayerState(index=0, pos=Vec2()),
        PlayerState(index=1, pos=Vec2()),
        PlayerState(index=2, pos=Vec2(), shield_timer=1.0),
    ]

    assert bonus_pick_random_type(state.bonus_pool, state, players) == BonusId.SHIELD
