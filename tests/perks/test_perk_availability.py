from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.availability import perk_can_offer
from crimson.quests.level import QuestLevel
from crimson.sim.gameplay_state import GameplayState


@pytest.mark.parametrize(
    ("perk_id", "expected"),
    [
        (PerkId.RANDOM_WEAPON, (True, True, False, False, True, True)),
        (PerkId.BREATHING_ROOM, (True, False, True, False, True, False)),
    ],
    ids=["random-weapon", "breathing-room"],
)
def test_mode_flags_match_native_allowlist_behavior(
    perk_id: PerkId,
    expected: tuple[bool, bool, bool, bool, bool, bool],
) -> None:
    state = GameplayState()
    (
        expected_survival_1p,
        expected_quest_1p,
        expected_survival_2p,
        expected_quest_2p,
        expected_survival_4p,
        expected_quest_4p,
    ) = expected
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=1) is expected_survival_1p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=1) is expected_quest_1p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=2) is expected_survival_2p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=2) is expected_quest_2p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.SURVIVAL, player_count=4) is expected_survival_4p
    assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=4) is expected_quest_4p


def test_hardcore_quest_2_10_blocks_poison_related_perks() -> None:
    baseline = GameplayState()
    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(baseline, perk_id, game_mode=GameMode.QUESTS, player_count=1) is True

    state = GameplayState()
    state.hardcore = True
    state.quest_level = QuestLevel(2, 10)

    for perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER):
        assert perk_can_offer(state, perk_id, game_mode=GameMode.QUESTS, player_count=1) is False
