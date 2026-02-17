from __future__ import annotations

from typing import cast

from ...game_modes import GameMode
from ...original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    apply_capture_bootstrap_payload,
    capture_bootstrap_payload_from_event_payload,
    capture_perk_apply_from_event_payload,
    capture_perk_pending_from_event_payload,
)
from ...perks import PerkId
from ...perks.runtime.apply import perk_apply
from ...perks.selection import perk_selection_current_choices, perk_selection_pick
from ...perks.state import CreatureForPerks
from ...replay import PerkMenuOpenEvent, PerkPickEvent, UnknownEvent
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
) -> int | None:
    state = world.state
    players = world.players
    perk_state = state.perk_selection
    bootstrap_elapsed_ms: int | None = None
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
                    # Some captures include a stale same-tick pick after a menu-open
                    # transition with no pending perks left. Treat it as a no-op.
                    if menu_open_seen and int(perk_state.pending_count) <= 0:
                        continue
                    raise ReplayRunnerError(f"perk_pick failed at tick={tick_index} choice_index={event.choice_index}")
                continue
            # UI parity quirk: after closing the menu, draw/update may query choices once more
            # during transition, consuming RNG and clearing `choices_dirty`.
            perk_selection_current_choices(
                state,
                players,
                perk_state,
                game_mode=int(game_mode_id),
                player_count=len(players),
            )
            continue

        if isinstance(event, UnknownEvent):
            kind = str(event.kind)

            if kind == CAPTURE_BOOTSTRAP_EVENT_KIND:
                payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
                if payload is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid bootstrap payload at tick={tick_index}")
                    continue
                elapsed = apply_capture_bootstrap_payload(payload, state=state, players=list(players))
                if elapsed is not None:
                    bootstrap_elapsed_ms = int(elapsed)
                continue

            if kind == CAPTURE_PERK_APPLY_EVENT_KIND:
                if int(game_mode_id) == int(GameMode.RUSH):
                    if strict_events:
                        raise ReplayRunnerError(f"unsupported perk_apply event in rush replay at tick={tick_index}")
                    continue

                parsed_perk_apply = capture_perk_apply_from_event_payload(list(event.payload))
                if parsed_perk_apply is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}")
                    continue
                perk_id, outside_before = parsed_perk_apply
                if perk_id <= 0:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}")
                    continue
                if not players:
                    continue
                try:
                    perk_enum = PerkId(int(perk_id))
                except ValueError as err:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}") from err
                    continue

                # `perk_apply_outside_before` draws are already accounted for by
                # capture inter-tick RNG overrides. Replaying Bandage RNG work a
                # second time here shifts gameplay RNG and causes later hit drift.
                if bool(outside_before) and perk_enum == PerkId.BANDAGE:
                    rng_state_before = int(state.rng.state)
                    perk_apply(
                        state,
                        players,
                        perk_enum,
                        perk_state=perk_state,
                        dt=float(dt_frame),
                        creatures=cast("list[CreatureForPerks]", world.creatures.entries),
                    )
                    state.rng.srand(int(rng_state_before))
                else:
                    perk_apply(
                        state,
                        players,
                        perk_enum,
                        perk_state=perk_state,
                        dt=float(dt_frame),
                        creatures=cast("list[CreatureForPerks]", world.creatures.entries),
                    )
                continue

            if kind == CAPTURE_PERK_PENDING_EVENT_KIND:
                if int(game_mode_id) == int(GameMode.RUSH):
                    if strict_events:
                        raise ReplayRunnerError(f"unsupported perk_pending event in rush replay at tick={tick_index}")
                    continue

                pending = capture_perk_pending_from_event_payload(list(event.payload))
                if pending is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid pending payload at tick={tick_index}")
                    continue
                if pending < 0:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid pending payload at tick={tick_index}")
                    continue
                perk_state.pending_count = int(pending)
                perk_state.choices_dirty = True
                continue

            if strict_events:
                raise ReplayRunnerError(f"unsupported replay event kind={event.kind!r} at tick={tick_index}")
            continue

        if strict_events:
            raise ReplayRunnerError(f"unsupported replay event type: {type(event).__name__}")

    return bootstrap_elapsed_ms


def partition_tick_events(
    events: list[object],
    *,
    defer_menu_open: bool,
) -> tuple[list[object], list[object]]:
    if not defer_menu_open:
        return list(events), []

    pre_step: list[object] = []
    post_step: list[object] = []
    for event in events:
        if isinstance(event, PerkMenuOpenEvent):
            # Original-capture traces call perk selection RNG on the transition to
            # menu state at the tail of the gameplay tick, after survival_update.
            post_step.append(event)
            continue
        pre_step.append(event)
    return pre_step, post_step
