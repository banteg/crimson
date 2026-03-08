from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.availability import perk_available_mask, unlocked_perk_ids


def test_perk_available_mask_excludes_antiperk_and_includes_base_pool(make_game_state) -> None:
    state = make_game_state()

    available = perk_available_mask(status=state.status)

    assert available[int(PerkId.BONUS_MAGNET)] is True
    assert available[int(PerkId.ANTIPERK)] is False


def test_unlocked_perk_ids_include_quest_unlocks(make_game_state) -> None:
    state = make_game_state()
    state.status.quest_unlock_index = 8

    perk_ids = unlocked_perk_ids(status=state.status)

    assert PerkId.URANIUM_FILLED_BULLETS in perk_ids
