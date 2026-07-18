from __future__ import annotations

import crimson.perks.selection as perk_selection_module
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.perks.selection import (
    PERK_ID_MAX,
    perk_generate_choices,
    perk_select_random,
    perk_selection_open_choices,
    perk_selection_pick,
    perk_selection_prepared_choices,
)
from crimson.perks.state import PerkSelectionState
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


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
    assert player.health == f32(0.1)
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


def test_perk_selection_open_choices_keeps_hidden_internal_entries(mocker) -> None:
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

    visible = perk_selection_open_choices(
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


def test_perk_selection_prepared_choices_is_pure_when_dirty() -> None:
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[PerkId.SHARPSHOOTER],
        choices_dirty=True,
    )

    visible = perk_selection_prepared_choices([player], perk_state)

    assert visible == []
    assert perk_state.choices == [PerkId.SHARPSHOOTER]
    assert perk_state.choices_dirty is True


def test_perk_selection_open_choices_generates_then_prepared_reads_without_regenerating(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(pending_count=1, choices=[], choices_dirty=True)
    generate_choices = mocker.patch.object(
        perk_selection_module,
        "perk_generate_choices",
        return_value=[
            PerkId.SHARPSHOOTER,
            PerkId.FASTSHOT,
            PerkId.AMMO_MANIAC,
            PerkId.LONG_DISTANCE_RUNNER,
            PerkId.TOUGH_RELOADER,
            PerkId.PERK_MASTER,
            PerkId.INSTANT_WINNER,
        ],
    )

    prepared = perk_selection_open_choices(
        state,
        [player],
        perk_state,
        game_mode=GameMode.SURVIVAL,
        player_count=1,
    )
    visible = perk_selection_prepared_choices([player], perk_state)

    assert prepared == visible
    assert generate_choices.call_count == 1


def test_perk_select_random_tags_exact_native_caller(mocker) -> None:
    rng = ScriptedCrand([0])
    state = GameplayState(rng=rng)
    state.perk_available = [False] * (PERK_ID_MAX + 1)
    state.perk_available[1] = True
    player = PlayerState(index=0, pos=Vec2())

    mocker.patch.object(perk_selection_module, "perk_can_offer", return_value=True)

    perk_id = perk_select_random(state, player, game_mode=GameMode.SURVIVAL, player_count=1)

    assert perk_id == PerkId.BLOODY_MESS_QUICK_LEARNER
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.PERK_SELECT_RANDOM]


def test_perk_selection_pick_prepares_choices_when_dirty(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[],
        choices_dirty=True,
    )
    mocker.patch.object(
        perk_selection_module,
        "perk_generate_choices",
        return_value=[PerkId.INSTANT_WINNER] * 7,
    )

    picked = perk_selection_pick(
        state,
        [player],
        perk_state,
        0,
        game_mode=GameMode.QUESTS,
        player_count=1,
    )

    assert picked == PerkId.INSTANT_WINNER
    assert player.perk_counts[int(PerkId.INSTANT_WINNER)] == 1


def test_perk_selection_pick_can_refresh_choices_to_preserve_rng_behavior(mocker) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    perk_state = PerkSelectionState(
        pending_count=1,
        choices=[],
        choices_dirty=True,
    )
    generate_choices = mocker.patch.object(
        perk_selection_module,
        "perk_generate_choices",
        side_effect=[
            [PerkId.INSTANT_WINNER] * 7,
            [PerkId.FASTSHOT] * 7,
        ],
    )

    picked = perk_selection_pick(
        state,
        [player],
        perk_state,
        0,
        game_mode=GameMode.QUESTS,
        player_count=1,
        refresh_choices=True,
    )

    assert picked == PerkId.INSTANT_WINNER
    assert perk_state.choices_dirty is False
    assert perk_state.choices == [PerkId.FASTSHOT] * 7
    assert generate_choices.call_count == 2


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
