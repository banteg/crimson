from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PerkSelectionState, PlayerState, perk_generate_choices, perk_selection_pick
from crimson.perks import PerkId


def test_perk_selection_pick_applies_perk_and_marks_dirty() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[int(PerkId.INSTANT_WINNER)],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [player], perk_state, 0, game_mode=3, player_count=1)

    assert picked == PerkId.INSTANT_WINNER
    assert perk_state.pending_count == 0
    assert perk_state.choices_dirty is True
    assert player.perk_counts[int(PerkId.INSTANT_WINNER)] == 1
    assert player.experience == 2500


def test_perk_selection_pick_infernal_contract_adds_pending_perks() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=100.0, level=1)
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[int(PerkId.INFERNAL_CONTRACT)],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [player], perk_state, 0, game_mode=3, player_count=1)

    assert picked == PerkId.INFERNAL_CONTRACT
    assert player.level == 4
    assert player.health == 0.1
    assert perk_state.pending_count == 3
    assert perk_state.choices_dirty is True


def test_perk_generate_choices_tutorial_returns_fixed_list() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))

    choices = perk_generate_choices(state, player, game_mode=int(GameMode.TUTORIAL), player_count=1)

    assert choices == [
        PerkId.SHARPSHOOTER,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.EVIL_EYES,
        PerkId.RADIOACTIVE,
        PerkId.FASTSHOT,
    ]


def test_perk_selection_pick_syncs_perk_counts_across_players() -> None:
    state = GameplayState()
    p1 = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=90.0)
    p2 = PlayerState(index=1, pos=Vec2(0.0, 0.0), health=60.0)
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[int(PerkId.THICK_SKINNED)],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [p1, p2], perk_state, 0, game_mode=3, player_count=2)

    assert picked == PerkId.THICK_SKINNED
    assert p1.perk_counts[int(PerkId.THICK_SKINNED)] == 1
    assert p2.perk_counts[int(PerkId.THICK_SKINNED)] == 1
    assert p1.health == pytest.approx(60.0)
    assert p2.health == pytest.approx(40.0)
