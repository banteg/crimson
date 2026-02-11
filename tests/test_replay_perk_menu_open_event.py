from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.gameplay import weapon_refresh_available
from crimson.perks import PerkId
from crimson.perks.availability import perks_rebuild_available
from crimson.perks.helpers import perk_count_get
from crimson.replay import PerkMenuOpenEvent, PerkPickEvent, UnknownEvent
from crimson.original.capture import (
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
)
from crimson.sim.runners.common import reset_players
from crimson.sim.runners.survival import _apply_tick_events
from crimson.sim.world_state import WorldState


def test_perk_menu_open_event_consumes_rng_for_choices() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.SURVIVAL)
    state.rng.srand(0x1234)
    weapon_refresh_available(state)
    perks_rebuild_available(state)

    before = int(state.rng.state)
    _apply_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        strict_events=True,
    )
    assert int(state.rng.state) != before
    assert not bool(state.perk_selection.choices_dirty)
    assert state.perk_selection.choices


def test_perk_pick_event_refreshes_choices_for_ui_transition_parity() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.SURVIVAL)
    state.rng.srand(0x1234)
    weapon_refresh_available(state)
    perks_rebuild_available(state)
    state.perk_selection.pending_count = 1
    state.perk_selection.choices_dirty = True

    _apply_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        strict_events=True,
    )
    choices_before_pick = list(state.perk_selection.choices)
    assert choices_before_pick

    _apply_tick_events(
        [PerkPickEvent(tick_index=1, player_index=0, choice_index=0)],
        tick_index=1,
        dt_frame=1.0 / 60.0,
        world=world,
        strict_events=True,
    )

    assert int(state.perk_selection.pending_count) == 0
    assert not bool(state.perk_selection.choices_dirty)
    assert state.perk_selection.choices


def test_original_capture_pending_event_sets_pending_without_pick_side_effects() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.SURVIVAL)
    state.perk_selection.pending_count = 2
    state.perk_selection.choices_dirty = False
    before_rng = int(state.rng.state)

    _apply_tick_events(
        [
            UnknownEvent(
                tick_index=5,
                kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                payload=[{"perk_pending": 0}],
            )
        ],
        tick_index=5,
        dt_frame=1.0 / 60.0,
        world=world,
        strict_events=True,
    )

    assert int(state.perk_selection.pending_count) == 0
    assert bool(state.perk_selection.choices_dirty)
    assert int(state.rng.state) == before_rng


def test_original_capture_perk_apply_event_applies_perk_without_rng_for_non_random_perks() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.SURVIVAL)
    state.perk_selection.pending_count = 1
    before_rng = int(state.rng.state)

    _apply_tick_events(
        [
            UnknownEvent(
                tick_index=7,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.FASTSHOT)}],
            )
        ],
        tick_index=7,
        dt_frame=1.0 / 60.0,
        world=world,
        strict_events=True,
    )

    assert perk_count_get(world.players[0], PerkId.FASTSHOT) == 1
    assert int(state.perk_selection.pending_count) == 1
    assert int(state.rng.state) == before_rng
