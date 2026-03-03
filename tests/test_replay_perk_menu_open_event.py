from __future__ import annotations

from typing import cast

import pytest

from crimson.game_modes import GameMode
from crimson.perks.availability import perks_rebuild_available
from crimson.replay import PerkMenuOpenEvent, PerkPickEvent, ReplayEvent
from crimson.sim.driver.replay_events import apply_replay_tick_events, partition_tick_events
from crimson.sim.driver.setup import ReplayRunnerError, reset_players
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_refresh_available


def _build_world(*, game_mode: GameMode = GameMode.SURVIVAL) -> WorldState:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, state=world.state, world_size=1024.0, player_count=1)
    state = world.state
    state.game_mode = int(game_mode)
    state.rng.srand(0x1234)
    weapon_refresh_available(state)
    perks_rebuild_available(state)
    return world


def test_perk_menu_open_event_consumes_rng_for_choices() -> None:
    world = _build_world()
    state = world.state

    before = int(state.rng.state)
    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt=1.0 / 60.0,
        world=world,
        game_mode_id=GameMode.SURVIVAL,
    )

    assert int(state.rng.state) != before
    assert not bool(state.perk_selection.choices_dirty)
    assert state.perk_selection.choices


def test_partition_tick_events_defers_only_menu_open_events() -> None:
    events = [
        PerkPickEvent(tick_index=0, player_index=0, choice_index=0),
        PerkMenuOpenEvent(tick_index=0, player_index=0),
    ]

    pre_step, post_step = partition_tick_events(events, defer_menu_open=True)
    assert pre_step == [events[0]]
    assert post_step == [events[1]]

    pre_step_no_defer, post_step_no_defer = partition_tick_events(events, defer_menu_open=False)
    assert pre_step_no_defer == events
    assert post_step_no_defer == []


def test_perk_pick_event_refreshes_choices_for_ui_transition_parity() -> None:
    world = _build_world()
    state = world.state
    state.perk_selection.pending_count = 1
    state.perk_selection.choices_dirty = True

    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt=1.0 / 60.0,
        world=world,
        game_mode_id=GameMode.SURVIVAL,
    )

    apply_replay_tick_events(
        [PerkPickEvent(tick_index=1, player_index=0, choice_index=0)],
        tick_index=1,
        dt=1.0 / 60.0,
        world=world,
        game_mode_id=GameMode.SURVIVAL,
    )

    assert int(state.perk_selection.pending_count) == 0
    assert not bool(state.perk_selection.choices_dirty)
    assert state.perk_selection.choices


def test_same_tick_stale_perk_pick_after_menu_open_is_noop_in_strict_mode() -> None:
    menu_only_world = _build_world()
    stale_pick_world = _build_world()

    menu_only_world.state.perk_selection.pending_count = 0
    stale_pick_world.state.perk_selection.pending_count = 0
    menu_only_world.state.perk_selection.choices_dirty = True
    stale_pick_world.state.perk_selection.choices_dirty = True

    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt=1.0 / 60.0,
        world=menu_only_world,
        game_mode_id=GameMode.SURVIVAL,
    )

    apply_replay_tick_events(
        [
            PerkMenuOpenEvent(tick_index=0, player_index=0),
            PerkPickEvent(tick_index=0, player_index=0, choice_index=1),
        ],
        tick_index=0,
        dt=1.0 / 60.0,
        world=stale_pick_world,
        game_mode_id=GameMode.SURVIVAL,
    )

    assert int(stale_pick_world.state.rng.state) == int(menu_only_world.state.rng.state)
    assert int(stale_pick_world.state.perk_selection.pending_count) == int(
        menu_only_world.state.perk_selection.pending_count,
    )
    assert bool(stale_pick_world.state.perk_selection.choices_dirty) == bool(
        menu_only_world.state.perk_selection.choices_dirty,
    )
    assert stale_pick_world.state.perk_selection.choices == menu_only_world.state.perk_selection.choices


def test_apply_replay_tick_events_rejects_unknown_event_type_in_strict_mode() -> None:
    world = _build_world()
    with pytest.raises(ReplayRunnerError, match="unsupported replay event type"):
        apply_replay_tick_events(
            [cast("ReplayEvent", object())],
            tick_index=0,
            dt=1.0 / 60.0,
            world=world,
            game_mode_id=GameMode.SURVIVAL,
        )
