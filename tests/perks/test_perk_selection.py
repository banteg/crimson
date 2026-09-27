from __future__ import annotations

import crimson.perks.selection as perk_selection_module
from crimson.game_modes import GameMode
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
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_perk_selection_pick_applies_perk_and_marks_dirty() -> None:
    state = GameplayState(
        perk_selection=PerkSelectionState(
            pending_count=1,
            choices=[PerkId.INSTANT_WINNER],
            choices_dirty=False,
        ),
    )
    perk_state = state.perk_selection
    player = PlayerState(index=0, pos=Vec2())

    picked = perk_selection_pick(state, [player], 0, game_mode=GameMode.QUESTS, dt=0.0, creatures=[])

    assert picked == PerkId.INSTANT_WINNER
    assert perk_state.pending_count == 0
    assert perk_state.choices_dirty is True
    assert state.perks[int(PerkId.INSTANT_WINNER)] == 1
    assert player.experience == 2500


def test_perk_selection_pick_infernal_contract_adds_pending_perks() -> None:
    state = GameplayState(
        perk_selection=PerkSelectionState(
            pending_count=1,
            choices=[PerkId.INFERNAL_CONTRACT],
            choices_dirty=False,
        ),
    )
    perk_state = state.perk_selection
    player = PlayerState(index=0, pos=Vec2(), health=100.0, level=1)

    picked = perk_selection_pick(state, [player], 0, game_mode=GameMode.QUESTS, dt=0.0, creatures=[])

    assert picked == PerkId.INFERNAL_CONTRACT
    assert player.level == 4
    assert player.health == f32(0.1)
    assert perk_state.pending_count == 3
    assert perk_state.choices_dirty is True


def test_perk_generate_choices_tutorial_returns_fixed_list() -> None:
    world = make_world()

    choices = perk_generate_choices(world.state, world.players, game_mode=GameMode.TUTORIAL)

    # The native 7-entry array; the selection screen shows the first five.
    assert choices == [
        PerkId.SHARPSHOOTER,
        PerkId.LONG_DISTANCE_RUNNER,
        PerkId.EVIL_EYES,
        PerkId.RADIOACTIVE,
        PerkId.FASTSHOT,
        PerkId.FASTSHOT,
        PerkId.FASTSHOT,
    ]


def test_perk_selection_open_choices_keeps_hidden_internal_entries() -> None:
    world = make_world()
    state = world.state
    state.perk_selection = PerkSelectionState(pending_count=1, choices=[], choices_dirty=True)

    visible = perk_selection_open_choices(state, world.players, game_mode=GameMode.SURVIVAL)

    assert len(state.perk_selection.choices) == 7
    assert visible == state.perk_selection.choices[:5]
    assert state.perk_selection.choices_dirty is False


def test_perk_selection_prepared_choices_is_pure_when_dirty() -> None:
    state = GameplayState(
        perk_selection=PerkSelectionState(
            pending_count=1,
            choices=[PerkId.SHARPSHOOTER],
            choices_dirty=True,
        ),
    )

    visible = perk_selection_prepared_choices(state)

    assert visible == []
    assert state.perk_selection.choices == [PerkId.SHARPSHOOTER]
    assert state.perk_selection.choices_dirty is True


def test_perk_selection_open_choices_generates_then_prepared_reads_without_regenerating() -> None:
    world = make_world()
    state = world.state
    state.perk_selection = PerkSelectionState(pending_count=1, choices=[], choices_dirty=True)

    rng_before = state.rng.state
    prepared = perk_selection_open_choices(state, world.players, game_mode=GameMode.SURVIVAL)
    rng_after_open = state.rng.state
    visible = perk_selection_prepared_choices(state)
    reopened = perk_selection_open_choices(state, world.players, game_mode=GameMode.SURVIVAL)

    assert rng_after_open != rng_before
    assert prepared == visible == reopened
    assert state.rng.state == rng_after_open


def test_perk_select_random_tags_exact_native_caller(mocker) -> None:
    rng = ScriptedCrand([0])
    state = GameplayState(rng=rng)
    state.perk_available = [False] * (PERK_ID_MAX + 1)
    state.perk_available[1] = True

    mocker.patch.object(perk_selection_module, "perk_can_offer", return_value=True)

    perk_id = perk_select_random(state, game_mode=GameMode.SURVIVAL, player_count=1)

    assert perk_id == PerkId.BLOODY_MESS_QUICK_LEARNER
    assert [record.caller for record in rng.records_since()] == [RngCallerStatic.PERK_SELECT_RANDOM]


def test_perk_selection_pick_prepares_choices_when_dirty() -> None:
    expected_world = make_world()
    expected = perk_generate_choices(expected_world.state, expected_world.players, game_mode=GameMode.QUESTS)

    world = make_world()
    state = world.state
    state.perk_selection = PerkSelectionState(pending_count=1, choices=[], choices_dirty=True)

    picked = perk_selection_pick(state, world.players, 0, game_mode=GameMode.QUESTS, dt=0.0, creatures=[])

    assert picked == expected[0]
    assert state.perks[int(expected[0])] == 1


def test_perk_selection_open_choices_after_pick_regenerates_choices() -> None:
    # The selection UI reopens the choices after a pick; the dirty list is regenerated then.
    world = make_world()
    state = world.state
    state.perk_selection = PerkSelectionState(pending_count=2, choices=[], choices_dirty=True)
    first = perk_selection_open_choices(state, world.players, game_mode=GameMode.QUESTS)

    perk_selection_pick(state, world.players, 0, game_mode=GameMode.QUESTS, dt=0.0, creatures=[])
    assert state.perk_selection.choices_dirty is True
    rng_before = state.rng.state

    second = perk_selection_open_choices(state, world.players, game_mode=GameMode.QUESTS)

    assert state.perk_selection.choices_dirty is False
    assert len(state.perk_selection.choices) == 7
    assert state.rng.state != rng_before
    assert second != first


def test_perk_selection_pick_thick_skinned_scales_every_player_health() -> None:
    state = GameplayState(
        perk_selection=PerkSelectionState(
            pending_count=1,
            choices=[PerkId.THICK_SKINNED],
            choices_dirty=False,
        ),
    )
    p1 = PlayerState(index=0, pos=Vec2(), health=90.0)
    p2 = PlayerState(index=1, pos=Vec2(), health=60.0)

    picked = perk_selection_pick(state, [p1, p2], 0, game_mode=GameMode.QUESTS, dt=0.0, creatures=[])

    assert picked == PerkId.THICK_SKINNED
    assert state.perks[int(PerkId.THICK_SKINNED)] == 1
    assert_float_close(p1.health, 60.0)
    assert_float_close(p2.health, 40.0)
