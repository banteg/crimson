from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.gameplay import perks_rebuild_available, weapon_refresh_available
from crimson.replay import PerkMenuOpenEvent, PerkPickEvent
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
