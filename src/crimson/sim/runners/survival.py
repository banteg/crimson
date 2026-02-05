from __future__ import annotations

from dataclasses import dataclass

from ...camera import camera_shake_update
from ...creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from ...game_modes import GameMode
from ...gameplay import (
    PlayerInput,
    perk_selection_current_choices,
    perk_selection_pick,
    perks_rebuild_available,
    weapon_refresh_available,
)
from ...replay import PerkMenuOpenEvent, PerkPickEvent, Replay, UnknownEvent, unpack_input_flags, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ..world_state import WorldState
from .common import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
    time_scale_reflex_boost_bonus,
)


@dataclass(slots=True)
class SurvivalRunState:
    elapsed_ms: float = 0.0
    stage: int = 0
    spawn_cooldown_ms: float = 0.0


def _apply_tick_events(
    events: list[object],
    *,
    tick_index: int,
    dt_frame: float,
    world: WorldState,
    strict_events: bool,
) -> None:
    state = world.state
    players = world.players
    perk_state = state.perk_selection

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
                creatures=world.creatures.entries,
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
            if strict_events:
                raise ReplayRunnerError(f"unsupported replay event kind={event.kind!r} at tick={tick_index}")
            continue
        if strict_events:
            raise ReplayRunnerError(f"unsupported replay event type: {type(event).__name__}")


def run_survival_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    strict_events: bool = True,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
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
    dt_frame_ms = dt_frame * 1000.0

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

    run = SurvivalRunState()

    events_by_tick: dict[int, list[object]] = {}
    for event in replay.events:
        events_by_tick.setdefault(int(event.tick_index), []).append(event)

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))

    for tick_index in range(tick_limit):
        # Mode state uses real dt (pre time-scale) for score timing + spawns.
        run.elapsed_ms += float(dt_frame_ms)

        state = world.state
        state.game_mode = int(GameMode.SURVIVAL)
        state.demo_mode_active = False

        _apply_tick_events(
            events_by_tick.get(tick_index, []),
            tick_index=tick_index,
            dt_frame=dt_frame,
            world=world,
            strict_events=bool(strict_events),
        )

        packed_tick = inputs[tick_index]
        player_inputs: list[PlayerInput] = []
        for packed in packed_tick:
            mx, my, ax, ay, flags = packed[:5]
            fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
            player_inputs.append(
                PlayerInput(
                    move_x=float(mx),
                    move_y=float(my),
                    aim_x=float(ax),
                    aim_y=float(ay),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=reload_pressed,
                )
            )

        rng_before_world_step = int(state.rng.state)
        world_step_marks: dict[str, int] = {"gw_begin": int(rng_before_world_step)}
        weapon_refresh_available(state)
        world_step_marks["gw_after_weapon_refresh"] = int(state.rng.state)
        perks_rebuild_available(state)
        world_step_marks["gw_after_perks_rebuild"] = int(state.rng.state)
        dt_sim = time_scale_reflex_boost_bonus(state, dt_frame)
        world_step_marks["gw_after_time_scale"] = int(state.rng.state)
        events = world.step(
            dt_sim,
            inputs=player_inputs,
            world_size=world_size,
            damage_scale_by_type=damage_scale_by_type,
            detail_preset=5,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
            rng_marks=world_step_marks,
        )
        # `GameWorld.update` runs `camera_shake_update` after world simulation and
        # before replay checkpoints are sampled in live recording paths.
        camera_shake_update(state, dt_sim)
        rng_after_world_step = int(state.rng.state)
        # Live gameplay clears terrain FX queues during render (`bake_fx_queues(clear=True)`).
        # Headless verification has no render pass, so clear explicitly per simulated tick.
        fx_queue.clear()
        fx_queue_rotated.clear()

        # Scripted milestone spawns based on level.
        player_level = world.players[0].level if world.players else 1
        stage, milestone_calls = advance_survival_spawn_stage(run.stage, player_level=int(player_level))
        run.stage = stage
        for call in milestone_calls:
            world.creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                state.rng,
                rand=state.rng.rand,
            )
        rng_after_stage_spawns = int(state.rng.state)

        # Regular wave spawns based on elapsed time.
        player_xp = world.players[0].experience if world.players else 0
        cooldown, wave_spawns = tick_survival_wave_spawns(
            run.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=run.elapsed_ms,
            player_experience=int(player_xp),
            terrain_width=int(world_size),
            terrain_height=int(world_size),
        )
        run.spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(wave_spawns)
        rng_after_wave_spawns = int(state.rng.state)

        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(run.elapsed_ms),
                    rng_marks={
                        "before_world_step": int(rng_before_world_step),
                        **world_step_marks,
                        "after_world_step": int(rng_after_world_step),
                        "after_stage_spawns": int(rng_after_stage_spawns),
                        "after_wave_spawns": int(rng_after_wave_spawns),
                    },
                    deaths=events.deaths,
                    events=events,
                )
            )

        if not any(player.health > 0.0 for player in world.players):
            tick_index += 1
            break
    else:
        tick_index = tick_limit

    shots_fired, shots_hit = player0_shots(world.state)
    most_used_weapon_id = player0_most_used_weapon_id(world.state, world.players)
    score_xp = int(world.players[0].experience) if world.players else 0

    return RunResult(
        game_mode_id=int(GameMode.SURVIVAL),
        tick_rate=tick_rate,
        ticks=int(tick_index),
        elapsed_ms=int(run.elapsed_ms),
        score_xp=score_xp,
        creature_kill_count=int(world.creatures.kill_count),
        most_used_weapon_id=int(most_used_weapon_id),
        shots_fired=int(shots_fired),
        shots_hit=int(shots_hit),
        rng_state=int(world.state.rng.state),
    )
