from __future__ import annotations

from dataclasses import dataclass

from ...creatures.spawn import tick_rush_mode_spawns
from ...game_modes import GameMode
from ...gameplay import PlayerInput, perks_rebuild_available, weapon_assign_player, weapon_refresh_available
from ...replay import Replay, unpack_input_flags, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...weapons import WeaponId
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

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE


@dataclass(slots=True)
class RushRunState:
    elapsed_ms: float = 0.0
    spawn_cooldown_ms: float = 0.0


def _enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if int(player.weapon_id) != int(RUSH_WEAPON_ID):
            weapon_assign_player(player, int(RUSH_WEAPON_ID))
        # `rush_mode_update` forces weapon+ammo every frame; keep ammo topped up.
        player.ammo = float(max(0, int(player.clip_size)))


def run_rush_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
) -> RunResult:
    if int(replay.header.game_mode_id) != int(GameMode.RUSH):
        raise ReplayRunnerError(
            f"replay game_mode_id={int(replay.header.game_mode_id)} does not match rush={int(GameMode.RUSH)}"
        )

    if warn_on_version_mismatch:
        warn_on_game_version_mismatch(replay, action="verification")

    if replay.events:
        raise ReplayRunnerError("rush replay does not support events")

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

    _enforce_rush_loadout(world)

    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    damage_scale_by_type = build_damage_scale_by_type()

    run = RushRunState()

    inputs = replay.inputs
    tick_limit = len(inputs) if max_ticks is None else min(len(inputs), max(0, int(max_ticks)))

    for tick_index in range(tick_limit):
        run.elapsed_ms += float(dt_frame_ms)

        state = world.state
        state.game_mode = int(GameMode.RUSH)
        state.demo_mode_active = False
        weapon_refresh_available(state)
        perks_rebuild_available(state)

        _enforce_rush_loadout(world)

        packed_tick = inputs[tick_index]
        player_inputs: list[PlayerInput] = []
        for packed in packed_tick:
            mx, my, ax, ay, flags = packed[:5]
            fire_down, fire_pressed, _reload_pressed = unpack_input_flags(int(flags))
            player_inputs.append(
                PlayerInput(
                    move_x=float(mx),
                    move_y=float(my),
                    aim_x=float(ax),
                    aim_y=float(ay),
                    fire_down=fire_down,
                    fire_pressed=fire_pressed,
                    reload_pressed=False,
                )
            )

        dt_sim = time_scale_reflex_boost_bonus(state, dt_frame)
        rng_before_world_step = int(state.rng.state)
        events = world.step(
            dt_sim,
            inputs=player_inputs,
            world_size=world_size,
            damage_scale_by_type=damage_scale_by_type,
            detail_preset=5,
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            auto_pick_perks=False,
            game_mode=int(GameMode.RUSH),
            perk_progression_enabled=False,
        )
        rng_after_world_step = int(state.rng.state)
        # Live gameplay clears terrain FX queues during render (`bake_fx_queues(clear=True)`).
        # Headless verification has no render pass, so clear explicitly per simulated tick.
        fx_queue.clear()
        fx_queue_rotated.clear()

        cooldown, spawns = tick_rush_mode_spawns(
            run.spawn_cooldown_ms,
            dt_frame_ms,
            state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=int(run.elapsed_ms),
            terrain_width=float(world_size),
            terrain_height=float(world_size),
        )
        run.spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(spawns)
        rng_after_rush_spawns = int(state.rng.state)

        if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_index) in checkpoint_ticks:
            checkpoints_out.append(
                build_checkpoint(
                    tick_index=int(tick_index),
                    world=world,
                    elapsed_ms=float(run.elapsed_ms),
                    rng_marks={
                        "before_world_step": int(rng_before_world_step),
                        "after_world_step": int(rng_after_world_step),
                        "after_rush_spawns": int(rng_after_rush_spawns),
                    },
                    deaths=events.deaths,
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
        game_mode_id=int(GameMode.RUSH),
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
