from __future__ import annotations

from pathlib import Path

import pytest
from grim.geom import Vec2

from crimson.creatures.spawn import advance_survival_spawn_stage, tick_rush_mode_spawns, tick_survival_wave_spawns
from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput, weapon_assign_player
from crimson.game_world import GameWorld
from crimson.replay import Replay, ReplayGameVersionWarning, ReplayHeader, ReplayRecorder, unpack_input_flags, unpack_packed_player_input
from crimson.replay.checkpoints import ReplayCheckpoint, build_checkpoint
from crimson.sim.runners import run_rush_replay, run_survival_replay
from crimson.sim.runners.common import status_from_snapshot
from crimson.weapons import WeaponId


def _build_replay(*, mode: int, ticks: int, seed: int = 0x1234) -> Replay:
    header = ReplayHeader(
        game_mode_id=int(mode),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version="0.0.0",
    )
    rec = ReplayRecorder(header)
    for idx in range(int(ticks)):
        rec.record_tick(
            [
                PlayerInput(
                    aim=Vec2(512.0 + float(idx), 512.0),
                    fire_down=bool(idx % 2 == 0),
                    fire_pressed=bool(idx % 3 == 0),
                    reload_pressed=bool(idx == int(ticks) - 1),
                )
            ]
        )
    return rec.finish()


def _inputs_for_tick(replay: Replay, tick_index: int) -> list[PlayerInput]:
    packed_tick = replay.inputs[int(tick_index)]
    inputs: list[PlayerInput] = []
    for packed in packed_tick:
        mx, my, ax, ay, flags = unpack_packed_player_input(packed)
        fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
        inputs.append(
            PlayerInput(
                move=Vec2(float(mx), float(my)),
                aim=Vec2(float(ax), float(ay)),
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
            )
        )
    return inputs


def _enforce_rush_loadout(world: GameWorld) -> None:
    for player in world.players:
        if int(player.weapon_id) != int(WeaponId.ASSAULT_RIFLE):
            weapon_assign_player(player, int(WeaponId.ASSAULT_RIFLE))
        player.ammo = float(max(0, int(player.clip_size)))


def _live_survival_checkpoints(replay: Replay) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt_frame = 1.0 / float(replay.header.tick_rate)
    dt_frame_ms = dt_frame * 1000.0
    elapsed_ms = 0.0
    stage = 0
    spawn_cooldown_ms = 0.0

    for tick_index in range(len(replay.inputs)):
        elapsed_before_ms = float(elapsed_ms)
        rng_before_world_step = int(world.state.rng.state)
        world_step_marks: dict[str, int] = {"before_world_step": int(rng_before_world_step)}
        world.update(
            dt_frame,
            inputs=_inputs_for_tick(replay, tick_index),
            auto_pick_perks=False,
            game_mode=int(GameMode.SURVIVAL),
            perk_progression_enabled=True,
            defer_camera_shake_update=True,
            rng_marks_out=world_step_marks,
        )
        world_events = world.last_events
        rng_after_world_step = int(world.state.rng.state)

        player_level = world.players[0].level if world.players else 1
        stage, milestone_calls = advance_survival_spawn_stage(stage, player_level=int(player_level))
        for call in milestone_calls:
            world.creatures.spawn_template(
                int(call.template_id),
                call.pos,
                float(call.heading),
                world.state.rng,
                rand=world.state.rng.rand,
            )
        rng_after_stage_spawns = int(world.state.rng.state)

        player_xp = world.players[0].experience if world.players else 0
        cooldown, wave_spawns = tick_survival_wave_spawns(
            spawn_cooldown_ms,
            dt_frame_ms,
            world.state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=elapsed_before_ms,
            player_experience=int(player_xp),
            terrain_width=int(world.world_size),
            terrain_height=int(world.world_size),
        )
        spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(wave_spawns)
        rng_after_wave_spawns = int(world.state.rng.state)
        elapsed_ms += float(dt_frame_ms)

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.world_state,
                elapsed_ms=float(elapsed_ms),
                rng_marks={
                    **world_step_marks,
                    "after_world_step": int(rng_after_world_step),
                    "after_stage_spawns": int(rng_after_stage_spawns),
                    "after_wave_spawns": int(rng_after_wave_spawns),
                },
                deaths=world_events.deaths,
                events=world_events,
                command_hash=str(world.last_command_hash),
            )
        )

    return checkpoints


def _live_rush_checkpoints(replay: Replay) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt_frame = 1.0 / float(replay.header.tick_rate)
    dt_frame_ms = dt_frame * 1000.0
    elapsed_ms = 0.0
    spawn_cooldown_ms = 0.0

    for tick_index in range(len(replay.inputs)):
        elapsed_ms += float(dt_frame_ms)
        _enforce_rush_loadout(world)
        rng_before_world_step = int(world.state.rng.state)
        world_step_marks: dict[str, int] = {"before_world_step": int(rng_before_world_step)}
        tick_inputs = _inputs_for_tick(replay, tick_index)
        rush_inputs = [
            PlayerInput(
                move=inp.move,
                aim=inp.aim,
                fire_down=bool(inp.fire_down),
                fire_pressed=bool(inp.fire_pressed),
                reload_pressed=False,
            )
            for inp in tick_inputs
        ]
        world.update(
            dt_frame,
            inputs=rush_inputs,
            auto_pick_perks=False,
            game_mode=int(GameMode.RUSH),
            perk_progression_enabled=False,
            defer_camera_shake_update=True,
            rng_marks_out=world_step_marks,
        )
        world_events = world.last_events
        rng_after_world_step = int(world.state.rng.state)

        cooldown, spawns = tick_rush_mode_spawns(
            spawn_cooldown_ms,
            dt_frame_ms,
            world.state.rng,
            player_count=len(world.players),
            survival_elapsed_ms=int(elapsed_ms),
            terrain_width=float(world.world_size),
            terrain_height=float(world.world_size),
        )
        spawn_cooldown_ms = cooldown
        world.creatures.spawn_inits(spawns)
        rng_after_rush_spawns = int(world.state.rng.state)

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.world_state,
                elapsed_ms=float(elapsed_ms),
                rng_marks={
                    **world_step_marks,
                    "after_world_step": int(rng_after_world_step),
                    "after_rush_spawns": int(rng_after_rush_spawns),
                },
                deaths=world_events.deaths,
                events=world_events,
                command_hash=str(world.last_command_hash),
            )
        )

    return checkpoints


def test_survival_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.SURVIVAL), ticks=6, seed=0x1234)

    live = _live_survival_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=True,
            checkpoints_out=headless,
            checkpoint_ticks=set(range(len(replay.inputs))),
        )

    assert [ck.state_hash for ck in live] == [ck.state_hash for ck in headless]
    assert [ck.command_hash for ck in live] == [ck.command_hash for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]


def test_rush_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.RUSH), ticks=6, seed=0x5678)

    live = _live_rush_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            checkpoints_out=headless,
            checkpoint_ticks=set(range(len(replay.inputs))),
        )

    assert [ck.state_hash for ck in live] == [ck.state_hash for ck in headless]
    assert [ck.command_hash for ck in live] == [ck.command_hash for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]
