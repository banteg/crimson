from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.original.capture import (
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
)
from crimson.perks import PerkId
from crimson.perks.availability import perks_rebuild_available
from crimson.perks.helpers import perk_count_get
from crimson.replay import PerkMenuOpenEvent, PerkPickEvent, UnknownEvent
from crimson.sim.driver.replay_events import apply_replay_tick_events
from crimson.sim.driver.setup import reset_players
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_refresh_available


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
    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
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

    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )
    choices_before_pick = list(state.perk_selection.choices)
    assert choices_before_pick

    apply_replay_tick_events(
        [PerkPickEvent(tick_index=1, player_index=0, choice_index=0)],
        tick_index=1,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    assert int(state.perk_selection.pending_count) == 0
    assert not bool(state.perk_selection.choices_dirty)
    assert state.perk_selection.choices


def test_same_tick_stale_perk_pick_after_menu_open_is_noop_in_strict_mode() -> None:
    def _build_world() -> WorldState:
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
        state.perk_selection.pending_count = 0
        state.perk_selection.choices_dirty = True
        return world

    menu_only_world = _build_world()
    stale_pick_world = _build_world()

    apply_replay_tick_events(
        [PerkMenuOpenEvent(tick_index=0, player_index=0)],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=menu_only_world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    apply_replay_tick_events(
        [
            PerkMenuOpenEvent(tick_index=0, player_index=0),
            PerkPickEvent(tick_index=0, player_index=0, choice_index=1),
        ],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=stale_pick_world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    assert int(stale_pick_world.state.rng.state) == int(menu_only_world.state.rng.state)
    assert int(stale_pick_world.state.perk_selection.pending_count) == int(menu_only_world.state.perk_selection.pending_count)
    assert bool(stale_pick_world.state.perk_selection.choices_dirty) == bool(menu_only_world.state.perk_selection.choices_dirty)
    assert stale_pick_world.state.perk_selection.choices == menu_only_world.state.perk_selection.choices


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

    apply_replay_tick_events(
        [
            UnknownEvent(
                tick_index=5,
                kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                payload=[{"perk_pending": 0}],
            ),
        ],
        tick_index=5,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    assert int(state.perk_selection.pending_count) == 0
    assert bool(state.perk_selection.choices_dirty)
    assert int(state.rng.state) == before_rng


def test_original_capture_pending_event_supported_in_quest_mode() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.QUESTS)
    state.perk_selection.pending_count = 2
    state.perk_selection.choices_dirty = False
    before_rng = int(state.rng.state)

    apply_replay_tick_events(
        [
            UnknownEvent(
                tick_index=5,
                kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                payload=[{"perk_pending": 0}],
            ),
        ],
        tick_index=5,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.QUESTS),
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

    apply_replay_tick_events(
        [
            UnknownEvent(
                tick_index=7,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.FASTSHOT)}],
            ),
        ],
        tick_index=7,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    assert perk_count_get(world.players[0], PerkId.FASTSHOT) == 1
    assert int(state.perk_selection.pending_count) == 1
    assert int(state.rng.state) == before_rng


def test_original_capture_perk_apply_event_supported_in_quest_mode() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
        preserve_bugs=False,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)

    state = world.state
    state.game_mode = int(GameMode.QUESTS)
    state.perk_selection.pending_count = 1
    before_rng = int(state.rng.state)

    apply_replay_tick_events(
        [
            UnknownEvent(
                tick_index=7,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.FASTSHOT)}],
            ),
        ],
        tick_index=7,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.QUESTS),
        strict_events=True,
    )

    assert perk_count_get(world.players[0], PerkId.FASTSHOT) == 1
    assert int(state.perk_selection.pending_count) == 1
    assert int(state.rng.state) == before_rng


def test_original_capture_outside_before_bandage_does_not_shift_rng_state() -> None:
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
    before_rng = int(state.rng.state)

    apply_replay_tick_events(
        [
            UnknownEvent(
                tick_index=9,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.BANDAGE), "outside_before": True}],
            ),
        ],
        tick_index=9,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.SURVIVAL),
        strict_events=True,
    )

    assert perk_count_get(world.players[0], PerkId.BANDAGE) == 1
    assert int(state.rng.state) == before_rng
