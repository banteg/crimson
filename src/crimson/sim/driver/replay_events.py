from __future__ import annotations

from collections.abc import Callable
from typing import cast

from grim.geom import Vec2

from ...creatures.spawn import CreatureFlags
from ...game_modes import GameMode
from ...math_parity import f32
from ...original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    CAPTURE_STATE_TRANSITION_EVENT_KIND,
    apply_capture_bootstrap_payload,
    capture_bootstrap_payload_from_event_payload,
    capture_creature_spawn_added_head_rows_from_event_payload,
    capture_creature_spawns_from_event_payload,
    capture_perk_apply_from_event_payload,
    capture_perk_pending_from_event_payload,
    capture_state_transitions_from_event_payload,
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
    on_capture_state_transition: Callable[[int, int | None, int | None], None] | None = None,
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

                # `perk_apply_outside_before` RNG draws are already replayed via
                # capture inter-tick RNG overrides. Apply perk side-effects but
                # keep RNG state anchored so we do not double-consume.
                rng_state_before: int | None = None
                if bool(outside_before):
                    rng_state_before = int(state.rng.state)
                perk_apply(
                    state,
                    players,
                    perk_enum,
                    perk_state=perk_state,
                    dt=float(dt_frame),
                    creatures=cast("list[CreatureForPerks]", world.creatures.entries),
                )
                if rng_state_before is not None:
                    state.rng.srand(int(rng_state_before))
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

            if kind == CAPTURE_CREATURE_SPAWN_EVENT_KIND:
                spawns = capture_creature_spawns_from_event_payload(list(event.payload))
                added_rows = capture_creature_spawn_added_head_rows_from_event_payload(list(event.payload))
                if spawns is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid creature_spawn payload at tick={tick_index}")
                    continue
                if added_rows is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid creature_spawn payload at tick={tick_index}")
                    continue
                for template_id, pos_x, pos_y, heading in spawns:
                    world.creatures.spawn_template(
                        int(template_id),
                        Vec2(float(pos_x), float(pos_y)),
                        float(heading),
                        state.rng,
                        rand=state.rng.rand,
                    )
                for row in added_rows:
                    index = row.get("index")
                    if not isinstance(index, int):
                        continue
                    idx = int(index)
                    if not (0 <= idx < len(world.creatures.entries)):
                        continue
                    entry = world.creatures.entries[idx]
                    if not entry.active:
                        continue
                    heading = row.get("heading")
                    target_heading = row.get("target_heading")
                    ai_mode = row.get("ai_mode")
                    link_index = row.get("link_index")
                    hp = row.get("hp")
                    hitbox_size = row.get("hitbox_size")
                    orbit_angle = row.get("orbit_angle")
                    orbit_radius = row.get("orbit_radius")
                    flags = row.get("flags")
                    type_id = row.get("type_id")
                    pos_raw = row.get("pos")

                    if isinstance(pos_raw, dict):
                        pos_obj = cast(dict[str, object], pos_raw)
                        pos_x = pos_obj.get("x")
                        pos_y = pos_obj.get("y")
                        if isinstance(pos_x, (int, float)) and isinstance(pos_y, (int, float)):
                            entry.pos = Vec2(float(f32(float(pos_x))), float(f32(float(pos_y))))
                    if isinstance(heading, (int, float)):
                        entry.heading = float(f32(float(heading)))
                    if isinstance(target_heading, (int, float)):
                        entry.target_heading = float(f32(float(target_heading)))
                    if isinstance(ai_mode, (int, float)):
                        entry.ai_mode = int(ai_mode)
                    if isinstance(link_index, (int, float)):
                        entry.link_index = int(link_index)
                    if isinstance(hp, (int, float)):
                        entry.hp = float(f32(float(hp)))
                    if isinstance(hitbox_size, (int, float)):
                        entry.hitbox_size = float(f32(float(hitbox_size)))
                    if isinstance(orbit_angle, (int, float)):
                        entry.orbit_angle = float(f32(float(orbit_angle)))
                    if isinstance(orbit_radius, (int, float)):
                        entry.orbit_radius = float(f32(float(orbit_radius)))
                    if isinstance(flags, (int, float)):
                        entry.flags = CreatureFlags(int(flags))
                    if isinstance(type_id, (int, float)):
                        entry.type_id = int(type_id)
                continue

            if kind == CAPTURE_STATE_TRANSITION_EVENT_KIND:
                transitions = capture_state_transitions_from_event_payload(list(event.payload))
                if transitions is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid state_transition payload at tick={tick_index}")
                    continue
                if on_capture_state_transition is not None:
                    for target_state, before_state, after_state in transitions:
                        on_capture_state_transition(int(target_state), before_state, after_state)
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
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_CREATURE_SPAWN_EVENT_KIND:
            # Original capture spawn hooks fire during quest_mode_update tail.
            post_step.append(event)
            continue
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_STATE_TRANSITION_EVENT_KIND:
            # Native state transitions are processed after the gameplay mode tick.
            post_step.append(event)
            continue
        pre_step.append(event)
    return pre_step, post_step
