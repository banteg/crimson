from __future__ import annotations

from typing import cast

from ...game_modes import GameMode
from ...perks.selection import perk_selection_current_choices, perk_selection_pick
from ...perks.state import CreatureForPerks
from ...replay import PerkMenuOpenEvent, PerkPickEvent
from ..world_state import WorldState
from .setup import ReplayRunnerError


def apply_replay_tick_events(
    events: list[object],
    *,
    tick_index: int,
    dt_frame: float,
    world: WorldState,
    game_mode_id: int,
    strict_events: bool,
    on_capture_state_transition=None,
) -> int | None:
    _ = on_capture_state_transition
    state = world.state
    players = world.players
    perk_state = state.perk_selection
    menu_open_seen = False

    for event in events:
        if isinstance(event, PerkMenuOpenEvent):
            menu_open_seen = True
            if int(game_mode_id) == int(GameMode.RUSH):
                if strict_events:
                    raise ReplayRunnerError(f"unsupported perk_menu_open in rush replay at tick={tick_index}")
                continue
            perk_selection_current_choices(
                state,
                players,
                perk_state,
                game_mode=int(game_mode_id),
                player_count=len(players),
            )
            continue

        if isinstance(event, PerkPickEvent):
            if int(game_mode_id) == int(GameMode.RUSH):
                if strict_events:
                    raise ReplayRunnerError(f"unsupported perk_pick in rush replay at tick={tick_index}")
                continue
            picked = perk_selection_pick(
                state,
                players,
                perk_state,
                int(event.choice_index),
                game_mode=int(game_mode_id),
                player_count=len(players),
                dt=float(dt_frame),
                creatures=cast("list[CreatureForPerks]", world.creatures.entries),
            )
            if picked is None:
                if strict_events:
                    if menu_open_seen and int(perk_state.pending_count) <= 0:
                        continue
                    raise ReplayRunnerError(f"perk_pick failed at tick={tick_index} choice_index={event.choice_index}")
                continue
            perk_selection_current_choices(
                state,
                players,
                perk_state,
                game_mode=int(game_mode_id),
                player_count=len(players),
            )
            continue

        if strict_events:
            raise ReplayRunnerError(f"unsupported replay event type: {type(event).__name__}")

    return None


def partition_tick_events(
    events: list[object],
    *,
    defer_menu_open: bool,
) -> tuple[list[object], list[object]]:
    if not defer_menu_open:
        return list(events), []

    pre_step: list[object] = []
    post_menu_open: list[object] = []
    for event in events:
        if isinstance(event, PerkMenuOpenEvent):
            post_menu_open.append(event)
            continue
        pre_step.append(event)
    return pre_step, post_menu_open
