from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.selection import (
    perk_selection_open_choices,
    perk_selection_pick,
    perk_selection_prepared_choices,
)
from crimson.perks.state import PerkSelectionState
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.helpers import assert_float_close


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

    assert picked is not None and picked.perk_id == PerkId.THICK_SKINNED
    assert state.perks[int(PerkId.THICK_SKINNED)] == 1
    assert_float_close(p1.health, 60.0)
    assert_float_close(p2.health, 40.0)
