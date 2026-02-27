from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from typing import cast

from ...bonuses.ids import BonusId, bonus_display_name
from ...game_modes import GameMode
from ...gameplay import build_gameplay_state
from ...original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    CAPTURE_STATE_TRANSITION_EVENT_KIND,
    capture_bootstrap_payload_from_event_payload,
    capture_state_transitions_from_event_payload,
    is_capture_state_reset_target,
)
from ...perks.ids import perk_display_name
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext
from ...replay import PerkMenuOpenEvent, Replay, UnknownEvent, apply_replay_bootstrap, unpack_tick_inputs
from ...weapon_runtime import weapon_assign_player
from ...weapons import WeaponId, weapon_display_name
from ..sessions import QuestDeterministicSession, RushDeterministicSession, SurvivalDeterministicSession
from ..state_types import BonusPickupEvent, PlayerState
from ..world_state import WorldState
from .replay_events import apply_replay_tick_events, partition_tick_events
from .replay_timing import resolve_dt_frame, resolve_dt_frame_ms_i32, should_apply_world_dt_steps_for_replay
from .setup import (
    ReplayRunnerError,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)

_EPSILON = 1e-6
_CORE_EVENT_KINDS = frozenset(
    (
        "bonus_pickup",
        "weapon_change",
        "perk_pick",
        "level_up",
        "health_damage",
        "health_heal",
        "player_death",
    ),
)

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE


@dataclass(frozen=True, slots=True)
class ReplayInfoTimelineEvent:
    tick_index: int
    elapsed_ms: int
    kind: str
    player_index: int | None
    detail: str
    data: dict[str, object]


@dataclass(frozen=True, slots=True)
class ReplayInfoResult:
    game_mode_id: int
    tick_rate: int
    ticks_simulated: int
    elapsed_ms: int
    player_count: int
    timeline: list[ReplayInfoTimelineEvent]


@dataclass(frozen=True, slots=True)
class _PlayerSnapshot:
    health: float
    level: int
    experience: int
    weapon_id: int
    perk_counts: tuple[int, ...]


def _resolve_quest_level(replay: Replay) -> str:
    quest_level = str(replay.header.quest_level)
    if quest_level:
        return str(quest_level)

    seed = int(replay.header.seed)
    major = seed // 100
    minor = seed % 100
    if 1 <= int(major) <= 5 and 1 <= int(minor) <= 10:
        return f"{major}.{minor}"
    return ""


def _enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if int(player.weapon_id) != int(RUSH_WEAPON_ID):
            weapon_assign_player(player, int(RUSH_WEAPON_ID))
        player.ammo = float(max(0, int(player.clip_size)))


def _capture_snapshots(players: list[PlayerState]) -> list[_PlayerSnapshot]:
    snapshots: list[_PlayerSnapshot] = []
    for player in players:
        snapshots.append(
            _PlayerSnapshot(
                health=float(player.health),
                level=int(player.level),
                experience=int(player.experience),
                weapon_id=int(player.weapon_id),
                perk_counts=tuple(int(value) for value in player.perk_counts),
            ),
        )
    return snapshots


def _append_event(
    timeline: list[ReplayInfoTimelineEvent],
    *,
    tick_index: int,
    elapsed_ms: int,
    kind: str,
    player_index: int | None,
    detail: str,
    data: dict[str, object],
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    if str(kind) not in _CORE_EVENT_KINDS and not bool(include_extra_events):
        return
    if player_filter is not None and player_index is not None and int(player_index) != int(player_filter):
        return
    timeline.append(
        ReplayInfoTimelineEvent(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            kind=str(kind),
            player_index=(None if player_index is None else int(player_index)),
            detail=str(detail),
            data=dict(data),
        ),
    )


def _append_extra_replay_events(
    *,
    tick_events: list[object],
    tick_index: int,
    elapsed_ms: int,
    timeline: list[ReplayInfoTimelineEvent],
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    if not bool(include_extra_events):
        return
    for event in tick_events:
        if isinstance(event, PerkMenuOpenEvent):
            player_idx = int(event.player_index)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="perk_menu_open",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} perk menu opened",
                data={"player_index": int(player_idx)},
                player_filter=player_filter,
                include_extra_events=True,
            )
            continue
        if not isinstance(event, UnknownEvent):
            continue
        if str(event.kind) != CAPTURE_STATE_TRANSITION_EVENT_KIND:
            continue
        transitions = capture_state_transitions_from_event_payload(list(event.payload))
        if transitions is None:
            continue
        for target_state, before_state, after_state in transitions:
            detail = (
                "state "
                f"{'?' if before_state is None else int(before_state)} -> "
                f"{'?' if after_state is None else int(after_state)} "
                f"(target={int(target_state)})"
            )
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="state_transition",
                player_index=None,
                detail=detail,
                data={
                    "target_state": int(target_state),
                    "before_state": (None if before_state is None else int(before_state)),
                    "after_state": (None if after_state is None else int(after_state)),
                },
                player_filter=player_filter,
                include_extra_events=True,
            )


def _append_bonus_pickup_events(
    *,
    tick_index: int,
    elapsed_ms: int,
    timeline: list[ReplayInfoTimelineEvent],
    pickups: list[BonusPickupEvent],
    preserve_bugs: bool,
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    for pickup in pickups:
        player_idx = int(pickup.player_index)
        bonus_id = int(pickup.bonus_id)
        amount = int(pickup.amount)
        bonus_name = bonus_display_name(int(bonus_id), preserve_bugs=bool(preserve_bugs))
        detail = f"p{int(player_idx)} picked {str(bonus_name)} ({int(bonus_id)}) amount={int(amount)}"
        data: dict[str, object] = {
            "bonus_id": int(bonus_id),
            "bonus_name": str(bonus_name),
            "amount": int(amount),
        }
        if int(bonus_id) == int(BonusId.WEAPON):
            weapon_id = int(amount)
            weapon_name = weapon_display_name(int(weapon_id), preserve_bugs=bool(preserve_bugs))
            detail += f" -> {str(weapon_name)}"
            data["weapon_id"] = int(weapon_id)
            data["weapon_name"] = str(weapon_name)
        _append_event(
            timeline,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            kind="bonus_pickup",
            player_index=int(player_idx),
            detail=detail,
            data=data,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )


def _append_snapshot_diff_events(
    *,
    tick_index: int,
    elapsed_ms: int,
    before: list[_PlayerSnapshot],
    after: list[_PlayerSnapshot],
    timeline: list[ReplayInfoTimelineEvent],
    preserve_bugs: bool,
    fx_toggle: int,
    player_filter: int | None,
    include_extra_events: bool,
) -> None:
    players_len = min(len(before), len(after))
    for idx in range(players_len):
        pre = before[idx]
        post = after[idx]
        player_idx = int(idx)

        if int(pre.weapon_id) != int(post.weapon_id):
            weapon_before_name = weapon_display_name(int(pre.weapon_id), preserve_bugs=bool(preserve_bugs))
            weapon_after_name = weapon_display_name(int(post.weapon_id), preserve_bugs=bool(preserve_bugs))
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="weapon_change",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} weapon {weapon_before_name} -> {weapon_after_name}",
                data={
                    "weapon_id_before": int(pre.weapon_id),
                    "weapon_name_before": str(weapon_before_name),
                    "weapon_id_after": int(post.weapon_id),
                    "weapon_name_after": str(weapon_after_name),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if int(post.level) > int(pre.level):
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="level_up",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} level {int(pre.level)} -> {int(post.level)} (xp={int(post.experience)})",
                data={
                    "level_before": int(pre.level),
                    "level_after": int(post.level),
                    "xp": int(post.experience),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        perk_len = min(len(pre.perk_counts), len(post.perk_counts))
        for perk_id in range(perk_len):
            before_count = int(pre.perk_counts[perk_id])
            after_count = int(post.perk_counts[perk_id])
            if int(after_count) <= int(before_count):
                continue
            perk_name = perk_display_name(
                int(perk_id),
                fx_toggle=int(fx_toggle),
                preserve_bugs=bool(preserve_bugs),
            )
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="perk_pick",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} perk {str(perk_name)} ({int(perk_id)}) x{int(after_count)}",
                data={
                    "perk_id": int(perk_id),
                    "perk_name": str(perk_name),
                    "count_before": int(before_count),
                    "count_after": int(after_count),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        health_before = float(pre.health)
        health_after = float(post.health)
        if float(health_after) < float(health_before) - float(_EPSILON):
            amount = float(health_before) - float(health_after)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="health_damage",
                player_index=int(player_idx),
                detail=(
                    f"p{int(player_idx)} damage {float(amount):.6f} "
                    f"(health {float(health_before):.6f}->{float(health_after):.6f})"
                ),
                data={
                    "amount": float(amount),
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        elif float(health_after) > float(health_before) + float(_EPSILON):
            amount = float(health_after) - float(health_before)
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="health_heal",
                player_index=int(player_idx),
                detail=(
                    f"p{int(player_idx)} heal {float(amount):.6f} "
                    f"(health {float(health_before):.6f}->{float(health_after):.6f})"
                ),
                data={
                    "amount": float(amount),
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )

        if float(health_before) > 0.0 and float(health_after) <= 0.0:
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="player_death",
                player_index=int(player_idx),
                detail=f"p{int(player_idx)} died (health {float(health_before):.6f}->{float(health_after):.6f})",
                data={
                    "health_before": float(health_before),
                    "health_after": float(health_after),
                },
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )


def _validate_player_filter(*, replay: Replay, player_index: int | None) -> int | None:
    if player_index is None:
        return None
    idx = int(player_index)
    if int(idx) < 0:
        raise ReplayRunnerError(f"invalid player_index filter: {player_index}")
    player_count = int(replay.header.player_count)
    if int(player_count) > 0 and int(idx) >= int(player_count):
        raise ReplayRunnerError(
            f"player_index filter out of range: {player_index} (player_count={int(player_count)})",
        )
    return int(idx)


def _run_survival_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None,
    strict_events: bool,
    player_filter: int | None,
    include_extra_events: bool,
) -> ReplayInfoResult:
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
    reset_players(world.players, world_size=world_size, player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    apply_replay_bootstrap(replay.header, rng=world.state.rng, world_size=float(world_size), strict=True)

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
        events_by_tick.setdefault(int(event.tick_index), []).append(event)

    apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=None,
        dt_frame_ms_i32_overrides=None,
    )
    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        game_tune_started=False,
        apply_world_dt_steps=bool(apply_world_dt_steps),
        clear_fx_queues_each_tick=True,
    )

    timeline: list[ReplayInfoTimelineEvent] = []
    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))
    for tick_index in range(tick_limit):
        world.state.game_mode = int(GameMode.SURVIVAL)
        world.state.demo_mode_active = False
        before = _capture_snapshots(world.players)

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=None,
        )
        tick_events = events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )

        apply_replay_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=bool(strict_events),
        )
        tick = session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=unpack_tick_inputs(inputs[tick_index]),
            trace_rng=False,
        )
        if post_step_events:
            apply_replay_tick_events(
                post_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=world,
                game_mode_id=int(GameMode.SURVIVAL),
                strict_events=bool(strict_events),
            )
        after = _capture_snapshots(world.players)

        elapsed_ms = int(tick.elapsed_ms)
        _append_extra_replay_events(
            tick_events=pre_step_events,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        _append_bonus_pickup_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            pickups=tick.step.events.pickups,
            preserve_bugs=bool(replay.header.preserve_bugs),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        if len(tick.step.events.deaths) > 0:
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="creature_deaths",
                player_index=None,
                detail=f"creature deaths={len(tick.step.events.deaths)}",
                data={"count": int(len(tick.step.events.deaths))},
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        _append_extra_replay_events(
            tick_events=post_step_events,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        _append_snapshot_diff_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            before=before,
            after=after,
            timeline=timeline,
            preserve_bugs=bool(replay.header.preserve_bugs),
            fx_toggle=int(replay.header.fx_toggle),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
    else:
        tick_index = tick_limit

    if int(tick_index) == int(len(inputs)):
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        terminal_events = events_by_tick.get(int(tick_index), [])
        apply_replay_tick_events(
            terminal_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=bool(strict_events),
        )
        _append_extra_replay_events(
            tick_events=terminal_events,
            tick_index=int(tick_index),
            elapsed_ms=int(session.elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

    return ReplayInfoResult(
        game_mode_id=int(GameMode.SURVIVAL),
        tick_rate=int(tick_rate),
        ticks_simulated=int(tick_index),
        elapsed_ms=int(session.elapsed_ms),
        player_count=int(len(world.players)),
        timeline=timeline,
    )


def _run_rush_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None,
    player_filter: int | None,
    include_extra_events: bool,
) -> ReplayInfoResult:
    events_by_tick: dict[int, list[UnknownEvent]] = {}
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            events_by_tick.setdefault(int(event.tick_index), []).append(event)
            continue
        raise ReplayRunnerError("rush replay does not support events")

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
    reset_players(world.players, world_size=world_size, player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    apply_replay_bootstrap(replay.header, rng=world.state.rng, world_size=float(world_size), strict=True)
    _enforce_rush_loadout(world)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = RushDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
        enforce_loadout=lambda: _enforce_rush_loadout(world),
    )

    timeline: list[ReplayInfoTimelineEvent] = []
    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))
    for tick_index in range(tick_limit):
        world.state.game_mode = int(GameMode.RUSH)
        world.state.demo_mode_active = False
        before = _capture_snapshots(world.players)

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        tick_events = cast("list[object]", events_by_tick.get(int(tick_index), []))
        apply_replay_tick_events(
            tick_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.RUSH),
            strict_events=True,
        )
        tick = session.step_tick(
            dt_frame=float(dt_tick),
            inputs=[replace(inp, reload_pressed=False) for inp in unpack_tick_inputs(inputs[tick_index])],
            trace_rng=False,
        )
        after = _capture_snapshots(world.players)

        elapsed_ms = int(tick.elapsed_ms)
        _append_bonus_pickup_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            pickups=tick.step.events.pickups,
            preserve_bugs=bool(replay.header.preserve_bugs),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        if len(tick.step.events.deaths) > 0:
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="creature_deaths",
                player_index=None,
                detail=f"creature deaths={len(tick.step.events.deaths)}",
                data={"count": int(len(tick.step.events.deaths))},
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        _append_snapshot_diff_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            before=before,
            after=after,
            timeline=timeline,
            preserve_bugs=bool(replay.header.preserve_bugs),
            fx_toggle=int(replay.header.fx_toggle),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
    else:
        tick_index = tick_limit

    apply_replay_tick_events(
        cast("list[object]", events_by_tick.get(int(tick_index), [])),
        tick_index=int(tick_index),
        dt_frame=float(dt_frame),
        world=world,
        game_mode_id=int(GameMode.RUSH),
        strict_events=True,
    )

    return ReplayInfoResult(
        game_mode_id=int(GameMode.RUSH),
        tick_rate=int(tick_rate),
        ticks_simulated=int(tick_index),
        elapsed_ms=int(session.elapsed_ms),
        player_count=int(len(world.players)),
        timeline=timeline,
    )


def _run_quest_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None,
    strict_events: bool,
    player_filter: int | None,
    include_extra_events: bool,
) -> ReplayInfoResult:
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
    reset_players(world.players, world_size=world_size, player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    world.state.rng.srand(int(replay.header.seed))

    quest_level = _resolve_quest_level(replay)
    quest = quest_by_level(quest_level) if quest_level else None
    if quest is None:
        raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={quest_level!r}")
    world.state.quest_stage_major, world.state.quest_stage_minor = quest.level_key
    quest_start_weapon_id = int(quest.start_weapon_id)
    ctx = QuestContext(
        width=int(world_size),
        height=int(world_size),
        player_count=int(replay.header.player_count),
    )
    spawn_entries = tuple(
        build_quest_spawn_table(
            quest,
            ctx,
            seed=int(replay.header.seed),
            hardcore=bool(replay.header.hardcore),
            full_version=True,
        ),
    )

    for player in world.players:
        weapon_assign_player(player, int(quest_start_weapon_id))

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    bootstrap_start_tick: int | None = None
    has_capture_creature_spawn_events = False
    for event in replay.events:
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
        if not isinstance(event, UnknownEvent):
            continue
        if str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
            tick_event = int(event.tick_index)
            if bootstrap_start_tick is None or tick_event < int(bootstrap_start_tick):
                bootstrap_start_tick = int(tick_event)
            continue
        if str(event.kind) == CAPTURE_CREATURE_SPAWN_EVENT_KIND:
            has_capture_creature_spawn_events = True

    apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=None,
        dt_frame_ms_i32_overrides=None,
    )
    capture_spawn_events_authoritative = bool(original_capture_replay) and bool(has_capture_creature_spawn_events)
    session_spawn_entries = tuple(spawn_entries)
    if capture_spawn_events_authoritative:
        session_spawn_entries = ()
    world.creatures.capture_spawn_events_authoritative = bool(capture_spawn_events_authoritative)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = QuestDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        spawn_entries=tuple(session_spawn_entries),
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        apply_world_dt_steps=bool(apply_world_dt_steps),
        clear_fx_queues_each_tick=True,
        finalize_post_render_lifecycle_each_tick=False,
    )
    reset_spawn_entries = tuple(session_spawn_entries)
    pending_capture_state_reset = False

    def _apply_capture_state_reset() -> None:
        nonlocal pending_capture_state_reset
        rng_state = int(world.state.rng.state)
        status = world.state.status
        game_mode = int(GameMode.QUESTS)
        demo_mode_active = bool(world.state.demo_mode_active)
        hardcore = bool(world.state.hardcore)
        preserve_bugs = bool(world.state.preserve_bugs)
        quest_stage_major_state = int(world.state.quest_stage_major)
        quest_stage_minor_state = int(world.state.quest_stage_minor)
        perk_pending = int(world.state.perk_selection.pending_count)
        perk_choices = list(world.state.perk_selection.choices)
        perk_choices_dirty = bool(world.state.perk_selection.choices_dirty)
        man_bomb_interval = float(world.state.perk_intervals.man_bomb)
        fire_cough_interval = float(world.state.perk_intervals.fire_cough)
        hot_tempered_interval = float(world.state.perk_intervals.hot_tempered)

        world.state = build_gameplay_state()
        world.state.rng.srand(int(rng_state))
        world.state.status = status
        world.state.game_mode = int(game_mode)
        world.state.demo_mode_active = bool(demo_mode_active)
        world.state.hardcore = bool(hardcore)
        world.state.preserve_bugs = bool(preserve_bugs)
        world.state.quest_stage_major = int(quest_stage_major_state)
        world.state.quest_stage_minor = int(quest_stage_minor_state)
        world.state.perk_selection.pending_count = int(perk_pending)
        world.state.perk_selection.choices = list(perk_choices)
        world.state.perk_selection.choices_dirty = bool(perk_choices_dirty)
        world.state.perk_intervals.man_bomb = float(man_bomb_interval)
        world.state.perk_intervals.fire_cough = float(fire_cough_interval)
        world.state.perk_intervals.hot_tempered = float(hot_tempered_interval)

        reset_players(world.players, world_size=float(world_size), player_count=int(replay.header.player_count))
        for player in world.players:
            weapon_assign_player(player, int(quest_start_weapon_id))
            if int(quest_start_weapon_id) == int(WeaponId.PISTOL):
                player.clip_size = max(12, int(player.clip_size))
                if float(player.ammo) < 12.0:
                    player.ammo = 12.0
        world.spawn_env = replace(world.spawn_env, difficulty_level=max(1, int(world.spawn_env.difficulty_level)))
        world.creatures.env = world.spawn_env
        world.creatures.effects = world.state.effects
        world.creatures.reset()
        world.creatures.capture_spawn_events_authoritative = bool(capture_spawn_events_authoritative)

        fx_queue.clear()
        fx_queue_rotated.clear()
        session.spawn_entries = tuple(reset_spawn_entries)
        session.spawn_timeline_ms = 0.0
        session.no_creatures_timer_ms = 0.0
        session.completion_transition_ms = -1.0
        pending_capture_state_reset = False

    def _on_capture_state_transition(target_state: int, _before_state: int | None, _after_state: int | None) -> None:
        nonlocal pending_capture_state_reset
        if not is_capture_state_reset_target(int(target_state)):
            return
        pending_capture_state_reset = True

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))
    tick_start = max(0, int(bootstrap_start_tick)) if bootstrap_start_tick is not None else 0

    if bootstrap_start_tick is not None:
        bootstrap_dt = resolve_dt_frame(
            tick_index=int(bootstrap_start_tick),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        bootstrap_dt_ms = float(bootstrap_dt) * 1000.0
        for event in events_by_tick.get(int(bootstrap_start_tick), []):
            if not (isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND):
                continue
            payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
            if payload is None:
                break
            if payload.quest_session is not None:
                session.spawn_timeline_ms = max(
                    0.0,
                    float(payload.quest_session.spawn_timeline_ms) - float(bootstrap_dt_ms),
                )
                session.no_creatures_timer_ms = max(
                    0.0,
                    float(payload.quest_session.no_creatures_timer_ms) - float(bootstrap_dt_ms),
                )
                completion_value = float(payload.quest_session.completion_transition_ms)
                if completion_value >= 0.0:
                    completion_value = max(0.0, float(completion_value) - float(bootstrap_dt_ms))
                session.completion_transition_ms = float(completion_value)
            break

    timeline: list[ReplayInfoTimelineEvent] = []
    for tick_index in range(int(tick_start), int(tick_limit)):
        if pending_capture_state_reset:
            _apply_capture_state_reset()

        world.state.game_mode = int(GameMode.QUESTS)
        world.state.demo_mode_active = False
        before = _capture_snapshots(world.players)

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=None,
        )
        tick_events = events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )
        apply_replay_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.QUESTS),
            strict_events=bool(strict_events),
            on_capture_state_transition=_on_capture_state_transition,
        )
        if pending_capture_state_reset:
            _apply_capture_state_reset()

        tick = session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=unpack_tick_inputs(inputs[tick_index]),
            trace_rng=False,
        )
        if post_step_events:
            apply_replay_tick_events(
                post_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=world,
                game_mode_id=int(GameMode.QUESTS),
                strict_events=bool(strict_events),
                on_capture_state_transition=_on_capture_state_transition,
            )
        world.creatures.finalize_post_render_lifecycle()
        after = _capture_snapshots(world.players)

        elapsed_ms = int(tick.elapsed_ms)
        _append_extra_replay_events(
            tick_events=pre_step_events,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        _append_bonus_pickup_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            pickups=tick.step.events.pickups,
            preserve_bugs=bool(replay.header.preserve_bugs),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        if len(tick.step.events.deaths) > 0:
            _append_event(
                timeline,
                tick_index=int(tick_index),
                elapsed_ms=int(elapsed_ms),
                kind="creature_deaths",
                player_index=None,
                detail=f"creature deaths={len(tick.step.events.deaths)}",
                data={"count": int(len(tick.step.events.deaths))},
                player_filter=player_filter,
                include_extra_events=include_extra_events,
            )
        _append_extra_replay_events(
            tick_events=post_step_events,
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
        _append_snapshot_diff_events(
            tick_index=int(tick_index),
            elapsed_ms=int(elapsed_ms),
            before=before,
            after=after,
            timeline=timeline,
            preserve_bugs=bool(replay.header.preserve_bugs),
            fx_toggle=int(replay.header.fx_toggle),
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )
    else:
        tick_index = tick_limit

    if int(tick_index) == int(len(inputs)):
        if pending_capture_state_reset:
            _apply_capture_state_reset()
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=None,
        )
        terminal_events = events_by_tick.get(int(tick_index), [])
        apply_replay_tick_events(
            terminal_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.QUESTS),
            strict_events=bool(strict_events),
            on_capture_state_transition=_on_capture_state_transition,
        )
        _append_extra_replay_events(
            tick_events=terminal_events,
            tick_index=int(tick_index),
            elapsed_ms=int(session.elapsed_ms),
            timeline=timeline,
            player_filter=player_filter,
            include_extra_events=include_extra_events,
        )

    return ReplayInfoResult(
        game_mode_id=int(GameMode.QUESTS),
        tick_rate=int(tick_rate),
        ticks_simulated=int(tick_index),
        elapsed_ms=int(session.elapsed_ms),
        player_count=int(len(world.players)),
        timeline=timeline,
    )


def run_replay_info(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    strict_events: bool = True,
    player_index: int | None = None,
    include_extra_events: bool = True,
) -> ReplayInfoResult:
    player_filter = _validate_player_filter(replay=replay, player_index=player_index)

    mode = int(replay.header.game_mode_id)
    if mode == int(GameMode.SURVIVAL):
        return _run_survival_replay_info(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            player_filter=player_filter,
            include_extra_events=bool(include_extra_events),
        )
    if mode == int(GameMode.RUSH):
        return _run_rush_replay_info(
            replay,
            max_ticks=max_ticks,
            player_filter=player_filter,
            include_extra_events=bool(include_extra_events),
        )
    if mode == int(GameMode.QUESTS):
        return _run_quest_replay_info(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            player_filter=player_filter,
            include_extra_events=bool(include_extra_events),
        )
    raise ReplayRunnerError(f"unsupported replay game_mode_id={mode}")


def event_counts_by_kind(timeline: list[ReplayInfoTimelineEvent]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for event in timeline:
        counts[str(event.kind)] += 1
    return dict(sorted(counts.items()))
