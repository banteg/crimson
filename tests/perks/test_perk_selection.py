from __future__ import annotations

import pytest

import crimson.perks.selection as perk_selection_module
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.selection import (
    perk_auto_pick,
    perk_generate_choices,
    perk_selection_current_choices,
    perk_selection_pick,
    perk_selection_visible_choices,
)
from crimson.perks.state import PerkSelectionState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import assert_float_close


def test_perk_selection_pick_applies_perk_and_marks_dirty() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.INSTANT_WINNER],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [player], perk_state, 0, game_mode=GameMode.QUESTS, player_count=1)

    assert picked == PerkId.INSTANT_WINNER
    assert perk_state.pending_count == 0
    assert perk_state.choices_dirty is True
    assert player.perk_counts[int(PerkId.INSTANT_WINNER)] == 1
    assert player.experience == 2500


def test_perk_selection_pick_returns_none_for_stale_pick() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=0,
        choices=[PerkId.INSTANT_WINNER],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [player], perk_state, 0, game_mode=GameMode.QUESTS, player_count=1)

    assert picked is None


def test_perk_selection_pick_fails_if_apply_consumes_pending_slot(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.INSTANT_WINNER],
        choices_dirty=False,
    )

    def _fake_apply(*_args: object, **_kwargs: object) -> None:
        perk_state.pending_count = 0

    mocker.patch.object(perk_selection_module, "perk_apply", side_effect=_fake_apply)

    with pytest.raises(RuntimeError, match="positive pending_count after perk_apply"):
        perk_selection_pick(state, [player], perk_state, 0, game_mode=GameMode.QUESTS, player_count=1)


def test_perk_selection_pick_infernal_contract_adds_pending_perks() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0, level=1)
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.INFERNAL_CONTRACT],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [player], perk_state, 0, game_mode=GameMode.QUESTS, player_count=1)

    assert picked == PerkId.INFERNAL_CONTRACT
    assert player.level == 4
    assert player.health == 0.1
    assert perk_state.pending_count == 3
    assert perk_state.choices_dirty is True


def test_perk_generate_choices_tutorial_returns_fixed_list() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())

    choices = perk_generate_choices(state, player, game_mode=GameMode.TUTORIAL, player_count=1)

    assert choices == [
        PerkId.SHARPSHOOTER,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.EVIL_EYES,
        PerkId.RADIOACTIVE,
        PerkId.FASTSHOT,
    ]


def test_perk_selection_current_choices_keeps_hidden_internal_entries(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(pending_count=1, choices=[], choices_dirty=True)

    def _fake_perk_generate_choices(*_args: object, **_kwargs: object) -> list[PerkId]:
        return [
            PerkId.SHARPSHOOTER,
            PerkId.FASTSHOT,
            PerkId.AMMO_MANIAC,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.TOUGH_RELOADER,
            PerkId.PERK_MASTER,
            PerkId.INSTANT_WINNER,
        ]

    mocker.patch.object(perk_selection_module, "perk_generate_choices", side_effect=_fake_perk_generate_choices)

    visible = perk_selection_current_choices(
        state,
        [player],
        perk_state,
        game_mode=GameMode.SURVIVAL,
        player_count=1,
    )

    assert visible == [
        PerkId.SHARPSHOOTER,
        PerkId.FASTSHOT,
        PerkId.AMMO_MANIAC,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.TOUGH_RELOADER,
    ]
    assert perk_state.choices == [
        PerkId.SHARPSHOOTER,
        PerkId.FASTSHOT,
        PerkId.AMMO_MANIAC,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.TOUGH_RELOADER,
        PerkId.PERK_MASTER,
        PerkId.INSTANT_WINNER,
    ]
    assert perk_state.choices_dirty is False


def test_perk_selection_visible_choices_keeps_existing_choices_without_regenerating(mocker) -> None:
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[
            PerkId.SHARPSHOOTER,
            PerkId.FASTSHOT,
            PerkId.AMMO_MANIAC,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.TOUGH_RELOADER,
            PerkId.PERK_MASTER,
            PerkId.INSTANT_WINNER,
        ],
        choices_dirty=True,
    )

    generate = mocker.patch.object(perk_selection_module, "perk_generate_choices")

    visible = perk_selection_visible_choices([player], perk_state)

    assert visible == [
        PerkId.SHARPSHOOTER,
        PerkId.FASTSHOT,
        PerkId.AMMO_MANIAC,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.TOUGH_RELOADER,
    ]
    generate.assert_not_called()
    assert perk_state.choices_dirty is True


def test_perk_selection_pick_syncs_perk_counts_across_players() -> None:
    state = GameplayState()
    p1 = PlayerState(index=0, pos=Vec2(), health=90.0)
    p2 = PlayerState(index=1, pos=Vec2(), health=60.0)
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.THICK_SKINNED],
        choices_dirty=False,
    )

    picked = perk_selection_pick(state, [p1, p2], perk_state, 0, game_mode=GameMode.QUESTS, player_count=2)

    assert picked == PerkId.THICK_SKINNED
    assert p1.perk_counts[int(PerkId.THICK_SKINNED)] == 1
    assert p2.perk_counts[int(PerkId.THICK_SKINNED)] == 1
    assert_float_close(p1.health, 60.0)
    assert_float_close(p2.health, 40.0)


def test_perk_selection_pick_raises_when_apply_breaks_pending_invariant(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.SHARPSHOOTER],
        choices_dirty=False,
    )

    def _broken_apply(*_args: object, **_kwargs: object) -> None:
        perk_state.pending_count = 0

    mocker.patch.object(perk_selection_module, "perk_apply", side_effect=_broken_apply)

    with pytest.raises(RuntimeError, match="pending_count"):
        perk_selection_pick(
            state,
            [player],
            perk_state,
            0,
            game_mode=GameMode.QUESTS,
            player_count=1,
        )


def test_perk_auto_pick_uses_visible_choices_only() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[
            PerkId.INSTANT_WINNER,
            PerkId.FASTSHOT,
            PerkId.AMMO_MANIAC,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.SHARPSHOOTER,
            PerkId.TOUGH_RELOADER,
            PerkId.PERK_MASTER,
        ],
        choices_dirty=False,
    )

    class _FixedRand(Crand):
        def __init__(self) -> None:
            super().__init__(0)

        def rand(self) -> int:
            return 6

    state.rng = _FixedRand()

    picks = perk_auto_pick(
        state,
        [player],
        perk_state,
        game_mode=GameMode.SURVIVAL,
        player_count=1,
    )

    assert picks == [PerkId.FASTSHOT]
    assert player.perk_counts[int(PerkId.FASTSHOT)] == 1
    assert player.perk_counts[int(PerkId.PERK_MASTER)] == 0
