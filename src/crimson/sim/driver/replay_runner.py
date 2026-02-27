from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import cast

from ...game_modes import GameMode
from ...gameplay import build_gameplay_state
from ...original.capture import (
    capture_bootstrap_payload_from_event_payload,
    is_capture_state_reset_target,
)
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext, SpawnEntry
from ...replay import (
    CaptureBootstrapEvent,
    CaptureCreatureSpawnEvent,
    Replay,
    apply_replay_bootstrap,
    unpack_tick_inputs,
    warn_on_game_version_mismatch,
)
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...weapon_runtime import weapon_assign_player
from ...weapons import WeaponId
from ..sessions import QuestDeterministicSession, RushDeterministicSession, SurvivalDeterministicSession
from ..world_state import WorldEvents, WorldState
from .replay_events import apply_replay_tick_events, partition_tick_events
from .replay_timing import resolve_dt_frame, resolve_dt_frame_ms_i32, should_apply_world_dt_steps_for_replay
from .setup import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
)

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE


def _enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if int(player.weapon_id) != int(RUSH_WEAPON_ID):
            weapon_assign_player(player, int(RUSH_WEAPON_ID))
        # `rush_mode_update` forces weapon+ammo every frame; keep ammo topped up.
        player.ammo = float(max(0, int(player.clip_size)))


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
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.SURVIVAL):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match survival={int(GameMode.SURVIVAL)}",
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
    apply_replay_bootstrap(
        replay.header,
        rng=world.state.rng,
        world_size=float(world_size),
        strict=True,
    )

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, CaptureBootstrapEvent):
            original_capture_replay = True
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
    apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=dt_frame_overrides,
        dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
    )

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        game_tune_started=False,
        apply_world_dt_steps=bool(apply_world_dt_steps),
        clear_fx_queues_each_tick=True,
    )

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

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
        )

        tick_events = events_by_tick.get(tick_index, [])
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )

        rng_before_events = int(state.rng.state)
        apply_replay_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=bool(strict_events),
        )
        rng_after_events = int(state.rng.state)

        player_inputs = unpack_tick_inputs(inputs[tick_index])

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
            apply_replay_tick_events(
                post_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=world,
                game_mode_id=int(GameMode.SURVIVAL),
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
                ),
            )
        if tick_observer is not None:
            tick_observer(int(tick_index), world)

        if inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                world.state.rng.rand()
        if tick_progress_callback is not None:
            tick_progress_callback(int(tick_index) + 1)
    else:
        tick_index = tick_limit

    # Some UI-side events (e.g. final perk picks) can be recorded at the
    # terminal boundary tick == len(inputs), after the last simulated input.
    if int(tick_index) == int(len(inputs)):
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        apply_replay_tick_events(
            events_by_tick.get(int(tick_index), []),
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.SURVIVAL),
            strict_events=bool(strict_events),
        )
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
                ),
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


def run_rush_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    trace_rng: bool = False,
    checkpoint_use_world_step_creature_count: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
    dt_frame_overrides: dict[int, float] | None = None,
    dt_frame_ms_i32_overrides: dict[int, int] | None = None,
    inter_tick_rand_draws: int = 0,
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.RUSH):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match rush={int(GameMode.RUSH)}",
        )

    if warn_on_version_mismatch:
        warn_on_game_version_mismatch(replay, action="verification")

    events_by_tick: dict[int, list[CaptureBootstrapEvent]] = {}
    for event in replay.events:
        if isinstance(event, CaptureBootstrapEvent):
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
    apply_replay_bootstrap(
        replay.header,
        rng=world.state.rng,
        world_size=float(world_size),
        strict=True,
    )

    _enforce_rush_loadout(world)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = RushDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        detail_preset=int(replay.header.detail_preset),
        fx_toggle=int(replay.header.fx_toggle),
        game_tune_started=False,
        clear_fx_queues_each_tick=True,
        enforce_loadout=lambda: _enforce_rush_loadout(world),
    )

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))

    for tick_index in range(tick_limit):
        state = world.state
        state.game_mode = int(GameMode.RUSH)
        state.demo_mode_active = False
        if inter_tick_rand_draws_by_tick is not None:
            draws = inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                world.state.rng.rand()
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
        )

        rng_before_events = int(state.rng.state)
        apply_replay_tick_events(
            cast("list[object]", events_by_tick.get(int(tick_index), [])),
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.RUSH),
            strict_events=True,
        )
        rng_after_events = int(state.rng.state)

        player_inputs = [replace(inp, reload_pressed=False) for inp in unpack_tick_inputs(inputs[tick_index])]

        tick = session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=player_inputs,
            trace_rng=bool(trace_rng),
        )
        step = tick.step
        events = step.events

        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoint_rng_marks = dict(tick.rng_marks)
            checkpoint_rng_marks["before_events"] = int(rng_before_events)
            checkpoint_rng_marks["after_events"] = int(rng_after_events)
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
                ),
            )
        if tick_observer is not None:
            tick_observer(int(tick_index), world)

        if inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                world.state.rng.rand()
        if tick_progress_callback is not None:
            tick_progress_callback(int(tick_index) + 1)
    else:
        tick_index = tick_limit

    rng_before_events = int(world.state.rng.state)
    apply_replay_tick_events(
        cast("list[object]", events_by_tick.get(int(tick_index), [])),
        tick_index=int(tick_index),
        dt_frame=float(dt_frame),
        world=world,
        game_mode_id=int(GameMode.RUSH),
        strict_events=True,
    )
    rng_after_events = int(world.state.rng.state)

    if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
        checkpoints_out.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world,
                elapsed_ms=float(session.elapsed_ms),
                rng_marks={"before_events": int(rng_before_events), "after_events": int(rng_after_events)},
                deaths=[],
                events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
                command_hash="",
            ),
        )

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    return RunResult(
        game_mode_id=int(GameMode.RUSH),
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


def _resolve_quest_level(replay: Replay) -> str:
    quest_level = str(replay.header.quest_level)
    if quest_level:
        return str(quest_level)

    # Legacy replays (e.g. capture-derived) may not encode the quest id. Classic quest RNG
    # seeding uses `major*100 + minor`, so we can often recover the level from `header.seed`.
    seed = int(replay.header.seed)
    major = seed // 100
    minor = seed % 100
    if 1 <= int(major) <= 5 and 1 <= int(minor) <= 10:
        return f"{major}.{minor}"
    return ""


def run_quest_replay(
    replay: Replay,
    *,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    quest_stage_major: int | None = None,
    quest_stage_minor: int | None = None,
    start_weapon_id: int | None = None,
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
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.QUESTS):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match quests={int(GameMode.QUESTS)}",
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

    if spawn_entries is None:
        quest_level = _resolve_quest_level(replay)
        quest = quest_by_level(quest_level) if quest_level else None
        if quest is None:
            raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={quest_level!r}")

        if quest_stage_major is None or quest_stage_minor is None:
            world.state.quest_stage_major, world.state.quest_stage_minor = quest.level_key
        if start_weapon_id is None:
            start_weapon_id = int(quest.start_weapon_id)

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
    else:
        spawn_entries = tuple(spawn_entries)

    if quest_stage_major is not None:
        world.state.quest_stage_major = int(quest_stage_major)
    if quest_stage_minor is not None:
        world.state.quest_stage_minor = int(quest_stage_minor)

    weapon_id = max(1, int(start_weapon_id or 1))
    for player in world.players:
        weapon_assign_player(player, weapon_id)
    quest_start_weapon_id = int(weapon_id)

    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    bootstrap_start_tick: int | None = None
    has_capture_creature_spawn_events = False
    for event in replay.events:
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
        if isinstance(event, CaptureBootstrapEvent):
            original_capture_replay = True
            tick_index = int(event.tick_index)
            if bootstrap_start_tick is None or tick_index < int(bootstrap_start_tick):
                bootstrap_start_tick = int(tick_index)
            continue
        if isinstance(event, CaptureCreatureSpawnEvent):
            has_capture_creature_spawn_events = True
    apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
        original_capture_replay=bool(original_capture_replay),
        dt_frame_overrides=dt_frame_overrides,
        dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
    )

    capture_spawn_events_authoritative = bool(original_capture_replay) and bool(has_capture_creature_spawn_events)
    session_spawn_entries = tuple(spawn_entries)
    if capture_spawn_events_authoritative:
        # Mid-capture quest replays do not encode native quest spawn-table RNG seed/state.
        # Use captured spawn hooks as authoritative and disable local quest-table spawning.
        session_spawn_entries = ()
    world.creatures.capture_spawn_events_authoritative = bool(capture_spawn_events_authoritative)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()
    session = QuestDeterministicSession(
        world=world,
        world_size=float(world_size),
        damage_scale_by_type=damage_scale_by_type,
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

        reset_players(
            world.players,
            world_size=float(world_size),
            player_count=int(replay.header.player_count),
        )
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

    def _on_capture_state_transition(
        target_state: int,
        _before_state: int | None,
        _after_state: int | None,
    ) -> None:
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
            dt_frame_overrides=dt_frame_overrides,
        )
        bootstrap_dt_ms = float(bootstrap_dt) * 1000.0
        for event in events_by_tick.get(int(bootstrap_start_tick), []):
            if not isinstance(event, CaptureBootstrapEvent):
                continue
            payload = capture_bootstrap_payload_from_event_payload(event)
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

    for tick_index in range(int(tick_start), int(tick_limit)):
        if pending_capture_state_reset:
            _apply_capture_state_reset()

        state = world.state
        state.game_mode = int(GameMode.QUESTS)
        state.demo_mode_active = False

        if inter_tick_rand_draws_by_tick is not None:
            draws = inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                world.state.rng.rand()

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=dt_frame_ms_i32_overrides,
        )

        tick_events = events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = partition_tick_events(
            tick_events,
            defer_menu_open=bool(original_capture_replay),
        )
        rng_before_events = int(state.rng.state)
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
            state = world.state
        rng_after_events = int(state.rng.state)

        player_inputs = unpack_tick_inputs(inputs[tick_index])

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
                    elapsed_ms=float(tick.spawn_timeline_ms),
                    creature_count_override=(
                        int(tick.creature_count_world_step) if checkpoint_use_world_step_creature_count else None
                    ),
                    rng_marks=checkpoint_rng_marks,
                    deaths=events.deaths,
                    events=events,
                    command_hash=str(step.command_hash),
                ),
            )
        if tick_observer is not None:
            tick_observer(int(tick_index), world)

        if inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(inter_tick_rand_draws))
            for _ in range(draws):
                world.state.rng.rand()
        if tick_progress_callback is not None:
            tick_progress_callback(int(tick_index) + 1)

    else:
        tick_index = tick_limit

    if int(tick_index) == int(len(inputs)):
        if pending_capture_state_reset:
            _apply_capture_state_reset()
        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(dt_frame),
            dt_frame_overrides=dt_frame_overrides,
        )
        apply_replay_tick_events(
            events_by_tick.get(int(tick_index), []),
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=world,
            game_mode_id=int(GameMode.QUESTS),
            strict_events=bool(strict_events),
            on_capture_state_transition=_on_capture_state_transition,
        )
        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(session.spawn_timeline_ms),
                    rng_marks={},
                    deaths=[],
                    events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
                    command_hash="",
                ),
            )

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    return RunResult(
        game_mode_id=int(GameMode.QUESTS),
        tick_rate=tick_rate,
        ticks=int(tick_index),
        elapsed_ms=int(session.spawn_timeline_ms),
        score_xp=score_xp,
        creature_kill_count=int(world.creatures.kill_count),
        most_used_weapon_id=int(most_used_weapon_id),
        shots_fired=int(shots_fired),
        shots_hit=int(shots_hit),
        rng_state=int(world.state.rng.state),
    )


def run_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    strict_events: bool = True,
    trace_rng: bool = False,
    checkpoint_use_world_step_creature_count: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
) -> RunResult:
    mode = int(replay.header.game_mode_id)
    if mode == int(GameMode.SURVIVAL):
        return run_survival_replay(
            replay,
            max_ticks=max_ticks,
            warn_on_version_mismatch=warn_on_version_mismatch,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
            checkpoints_out=checkpoints_out,
            checkpoint_ticks=checkpoint_ticks,
            tick_progress_callback=tick_progress_callback,
            tick_observer=tick_observer,
        )
    if mode == int(GameMode.RUSH):
        return run_rush_replay(
            replay,
            max_ticks=max_ticks,
            warn_on_version_mismatch=warn_on_version_mismatch,
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
            checkpoints_out=checkpoints_out,
            checkpoint_ticks=checkpoint_ticks,
            tick_progress_callback=tick_progress_callback,
            tick_observer=tick_observer,
        )
    if mode == int(GameMode.QUESTS):
        return run_quest_replay(
            replay,
            max_ticks=max_ticks,
            warn_on_version_mismatch=warn_on_version_mismatch,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
            checkpoints_out=checkpoints_out,
            checkpoint_ticks=checkpoint_ticks,
            tick_progress_callback=tick_progress_callback,
            tick_observer=tick_observer,
        )
    raise ReplayRunnerError(f"unsupported replay game_mode_id={mode}")
