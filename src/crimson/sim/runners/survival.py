from __future__ import annotations

import math
from typing import cast

from grim.geom import Vec2

from ...game_modes import GameMode
from ...perks import PerkId
from ...perks.runtime.apply import perk_apply
from ...perks.selection import perk_selection_current_choices, perk_selection_pick
from ...perks.state import CreatureForPerks
from ...replay import (
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    UnknownEvent,
    unpack_packed_player_input,
    unpack_input_flags,
    warn_on_game_version_mismatch,
)
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    apply_capture_bootstrap_payload,
    capture_bootstrap_payload_from_event_payload,
    capture_perk_apply_id_from_event_payload,
    capture_perk_pending_from_event_payload,
)
from ..input import PlayerInput
from ..sessions import SurvivalDeterministicSession
from ..world_state import WorldEvents, WorldState
from .common import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
)


def _apply_tick_events(
    events: list[object],
    *,
    tick_index: int,
    dt_frame: float,
    world: WorldState,
    strict_events: bool,
) -> int | None:
    state = world.state
    players = world.players
    perk_state = state.perk_selection
    bootstrap_elapsed_ms: int | None = None

    for event in events:
        if isinstance(event, PerkMenuOpenEvent):
            perk_selection_current_choices(
                state,
                players,
                perk_state,
                game_mode=int(GameMode.SURVIVAL),
                player_count=len(players),
            )
            continue
        if isinstance(event, PerkPickEvent):
            picked = perk_selection_pick(
                state,
                players,
                perk_state,
                int(event.choice_index),
                game_mode=int(GameMode.SURVIVAL),
                player_count=len(players),
                dt=float(dt_frame),
                creatures=cast("list[CreatureForPerks]", world.creatures.entries),
            )
            if picked is None:
                if strict_events:
                    raise ReplayRunnerError(f"perk_pick failed at tick={tick_index} choice_index={event.choice_index}")
                continue
            # UI parity quirk: after closing the menu, draw/update may query choices once more
            # during transition, consuming RNG and clearing `choices_dirty`.
            perk_selection_current_choices(
                state,
                players,
                perk_state,
                game_mode=int(GameMode.SURVIVAL),
                player_count=len(players),
            )
            continue
        if isinstance(event, UnknownEvent):
            if str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
                payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
                if payload is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid bootstrap payload at tick={tick_index}")
                    continue
                elapsed = apply_capture_bootstrap_payload(payload, state=state, players=list(players))
                if elapsed is not None:
                    bootstrap_elapsed_ms = int(elapsed)
                continue
            if str(event.kind) == CAPTURE_PERK_APPLY_EVENT_KIND:
                perk_id = capture_perk_apply_id_from_event_payload(list(event.payload))
                if perk_id is None:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}")
                    continue
                if perk_id <= 0:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}")
                    continue
                if not players:
                    continue
                try:
                    perk_enum = PerkId(int(perk_id))
                except ValueError:
                    if strict_events:
                        raise ReplayRunnerError(f"invalid perk_apply payload at tick={tick_index}")
                    continue
                perk_apply(
                    state,
                    players,
                    perk_enum,
                    perk_state=perk_state,
                    dt=float(dt_frame),
                    creatures=cast("list[CreatureForPerks]", world.creatures.entries),
                )
                continue
            if str(event.kind) == CAPTURE_PERK_PENDING_EVENT_KIND:
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


def _partition_tick_events(
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


def _resolve_dt_frame(
    *,
    tick_index: int,
    default_dt_frame: float,
    dt_frame_overrides: dict[int, float] | None,
) -> float:
    if not dt_frame_overrides:
        return float(default_dt_frame)
    override = dt_frame_overrides.get(int(tick_index))
    if override is None:
        return float(default_dt_frame)
    dt_frame = float(override)
    if not math.isfinite(dt_frame) or dt_frame <= 0.0:
        return float(default_dt_frame)
    return float(dt_frame)


def _resolve_dt_frame_ms_i32(
    *,
    tick_index: int,
    dt_frame: float,
    dt_frame_ms_i32_overrides: dict[int, int] | None,
) -> int | None:
    if dt_frame_ms_i32_overrides is None:
        return None
    if dt_frame_ms_i32_overrides:
        override = dt_frame_ms_i32_overrides.get(int(tick_index))
        if override is not None and int(override) > 0:
            return int(override)
    dt_ms_i32 = int(round(float(dt_frame) * 1000.0))
    if dt_ms_i32 <= 0:
        return 1
    return int(dt_ms_i32)


def run_survival_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    strict_events: bool = True,
    trace_rng: bool = False,
    checkpoint_use_world_step_creature_count: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
    dt_frame_overrides: dict[int, float] | None = None,
    dt_frame_ms_i32_overrides: dict[int, int] | None = None,
    inter_tick_rand_draws: int = 0,
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.SURVIVAL):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match survival={int(GameMode.SURVIVAL)}"
        )

    if warn_on_version_mismatch:
        warn_on_game_version_mismatch(replay, action="verification")

    tick_rate = int(replay.header.tick_rate)
    if tick_rate <= 0:
        raise ReplayRunnerError(f"invalid tick_rate: {tick_rate}")
    dt_frame = 1.0 / float(tick_rate)

    world_size = float(replay.header.world_size)
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=False,
        hardcore=bool(replay.header.hardcore),
        difficulty_level=int(replay.header.difficulty_level),
        preserve_bugs=bool(replay.header.preserve_bugs),
    )
    reset_players(
        world.players,
        world_size=world_size,
        player_count=int(replay.header.player_count),
    )
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    world.state.rng.srand(int(replay.header.seed))

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=5,
        fx_toggle=0,
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
    )

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
        events_by_tick.setdefault(int(event.tick_index), []).append(event)

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))

    for tick_index in range(tick_limit):
        state = world.state
        state.game_mode = int(GameMode.SURVIVAL)
        state.demo_mode_active = False
        if inter_tick_rand_draws_by_tick is not None:
            draws = inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                world.state.rng.rand()
        dt_tick = _resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = _resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
        )

        tick_events = events_by_tick.get(tick_index, [])
        pre_step_events, post_step_events = _partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )

        rng_before_events = int(state.rng.state)
        _apply_tick_events(
            pre_step_events,
            tick_index=tick_index,
            dt_frame=float(dt_tick),
            world=world,
            strict_events=bool(strict_events),
        )
        rng_after_events = int(state.rng.state)

        packed_tick = inputs[tick_index]
        player_inputs: list[PlayerInput] = []
        for packed in packed_tick:
            mx, my, ax, ay, flags = unpack_packed_player_input(packed)
            fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
            player_inputs.append(
                PlayerInput(
                    move=Vec2(float(mx), float(my)),
                    aim=Vec2(float(ax), float(ay)),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=reload_pressed,
                    move_forward_pressed=None,
                    move_backward_pressed=None,
                    turn_left_pressed=None,
                    turn_right_pressed=None,
                )
            )

        tick = session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=player_inputs,
            trace_rng=bool(trace_rng),
        )
        step = tick.step
        events = step.events

        rng_before_post_events = int(state.rng.state)
        if post_step_events:
            _apply_tick_events(
                post_step_events,
                tick_index=tick_index,
                dt_frame=float(dt_tick),
                world=world,
                strict_events=bool(strict_events),
            )
        rng_after_post_events = int(state.rng.state)

        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoint_rng_marks = dict(tick.rng_marks)
            checkpoint_rng_marks["before_events"] = int(rng_before_events)
            checkpoint_rng_marks["after_events"] = (
                int(rng_after_post_events) if post_step_events else int(rng_after_events)
            )
            if post_step_events:
                checkpoint_rng_marks["before_post_events"] = int(rng_before_post_events)
                checkpoint_rng_marks["after_post_events"] = int(rng_after_post_events)
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(tick.elapsed_ms),
                    creature_count_override=(
                        int(tick.creature_count_world_step) if checkpoint_use_world_step_creature_count else None
                    ),
                    rng_marks=checkpoint_rng_marks,
                    deaths=events.deaths,
                    events=events,
                    command_hash=str(step.command_hash),
                )
            )

        if inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                world.state.rng.rand()

        if not any(player.health > 0.0 for player in world.players):
            tick_index += 1
            break
    else:
        tick_index = tick_limit

    # Some UI-side events (e.g. final perk picks) can be recorded at the
    # terminal boundary tick == len(inputs), after the last simulated input.
    if int(tick_index) == int(len(inputs)):
        dt_tick = _resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        rng_before_events = int(world.state.rng.state)
        _apply_tick_events(
            events_by_tick.get(int(tick_index), []),
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            strict_events=bool(strict_events),
        )
        rng_after_events = int(world.state.rng.state)
        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(session.elapsed_ms),
                    rng_marks={},
                    deaths=[],
                    events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
                    command_hash="",
                )
            )

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    return RunResult(
        game_mode_id=int(GameMode.SURVIVAL),
        tick_rate=tick_rate,
        ticks=int(tick_index),
        elapsed_ms=int(session.elapsed_ms),
        score_xp=score_xp,
        creature_kill_count=int(world.creatures.kill_count),
        most_used_weapon_id=int(most_used_weapon_id),
        shots_fired=int(shots_fired),
        shots_hit=int(shots_hit),
        rng_state=int(world.state.rng.state),
    )
