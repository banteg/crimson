from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.creatures.spawn import advance_survival_spawn_stage, tick_survival_wave_spawns
from crimson.game_modes import GameMode
from crimson.game_world import GameWorld
from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import (
    Replay,
    ReplayHeader,
    ReplayRecorder,
    unpack_input_flags,
    unpack_packed_player_input,
)
from crimson.replay.checkpoints import ReplayCheckpoint, build_checkpoint
from crimson.sim.driver.playback_driver import resolve_quest_level_from_replay
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.driver.setup import status_from_snapshot
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import QuestDeterministicSession, RushDeterministicSession
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _build_replay(*, mode: int, ticks: int, seed: int = 0x1234) -> Replay:
    header = ReplayHeader(
        game_mode_id=GameMode(int(mode)),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
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
                ),
            ],
        )
    return rec.finish()


def _inputs_for_tick(replay: Replay, tick_index: int) -> list[PlayerInput]:
    packed_tick = replay.inputs[int(tick_index)]
    inputs: list[PlayerInput] = []
    for packed in packed_tick:
        mx, my, ax, ay, flags = unpack_packed_player_input(packed)
        fire_down, fire_pressed, reload_pressed, _reload_down = unpack_input_flags(int(flags))
        inputs.append(
            PlayerInput(
                move=Vec2(float(mx), float(my)),
                aim=Vec2(float(ax), float(ay)),
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
            ),
        )
    return inputs


def _enforce_rush_loadout(world: GameWorld) -> None:
    for player in world.players:
        if player.weapon.weapon_id != WeaponId.ASSAULT_RIFLE:
            weapon_assign_player(player, WeaponId.ASSAULT_RIFLE)
        player.weapon.ammo = 30.0


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
    dt = 1.0 / float(replay.header.tick_rate)
    dt_ms = dt * 1000.0
    elapsed_ms = 0.0
    stage = 0
    spawn_cooldown_ms = 0.0

    for tick_index in range(len(replay.inputs)):
        elapsed_before_ms = float(elapsed_ms)
        rng_before_world_step = int(world.state.rng.state)
        world_step_marks: dict[str, int] = {"before_world_step": int(rng_before_world_step)}
        world.update(
            dt,
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
            dt_ms,
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
        elapsed_ms += float(dt_ms)

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
            ),
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

    session = RushDeterministicSession(
        world=world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world._damage_scale_by_type,
        fx_queue=world.fx_queue,
        fx_queue_rotated=world.fx_queue_rotated,
        detail_preset=5,
        fx_toggle=0,
        clear_fx_queues_each_tick=True,
        enforce_loadout=lambda: _enforce_rush_loadout(world),
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt = 1.0 / float(replay.header.tick_rate)
    for tick_index in range(len(replay.inputs)):
        tick_inputs = _inputs_for_tick(replay, tick_index)
        rush_inputs = [msgspec.structs.replace(inp, reload_pressed=False) for inp in tick_inputs]
        timing = session.timing_for_dt(float(dt))
        tick = session.step_tick(
            timing=timing,
            inputs=rush_inputs,
            trace_rng=False,
        )
        step = tick.step
        world.apply_step_result(
            step,
            game_tune_started=bool(session.game_tune_started),
            apply_audio=False,
            update_camera=False,
        )
        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.world_state,
                elapsed_ms=float(tick.elapsed_ms),
                rng_marks=dict(tick.rng_marks),
                deaths=step.events.deaths,
                events=step.events,
                command_hash=str(step.command_hash),
            ),
        )

    return checkpoints


def _quest_spawn_entries(*, level: str, player_count: int, seed: int) -> tuple:
    quest = quest_by_level(level)
    assert quest is not None
    ctx = QuestContext(width=1024, height=1024, player_count=int(player_count))
    return tuple(
        build_quest_spawn_table(
            quest,
            ctx,
            seed=int(seed),
            hardcore=False,
            full_version=True,
        ),
    )


def _live_quest_checkpoints(replay: Replay, *, spawn_entries: tuple) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    quest_level = resolve_quest_level_from_replay(replay)
    quest = quest_by_level(quest_level) if quest_level else None
    if quest is not None:
        world.state.quest_stage_major = int(quest.level_key[0])
        world.state.quest_stage_minor = int(quest.level_key[1])
    weapon_id = quest.start_weapon_id if quest is not None else WeaponId.PISTOL
    for player in world.players:
        weapon_assign_player(player, weapon_id, state=world.state)

    session = QuestDeterministicSession(
        world=world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world._damage_scale_by_type,
        fx_queue=world.fx_queue,
        fx_queue_rotated=world.fx_queue_rotated,
        spawn_entries=tuple(spawn_entries),
        detail_preset=5,
        fx_toggle=0,
        clear_fx_queues_each_tick=True,
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt = 1.0 / float(replay.header.tick_rate)

    for tick_index in range(len(replay.inputs)):
        timing = session.timing_for_dt(float(dt))
        tick = session.step_tick(
            timing=timing,
            inputs=_inputs_for_tick(replay, tick_index),
            trace_rng=False,
        )
        step = tick.step

        world.apply_step_result(
            step,
            game_tune_started=False,
            apply_audio=False,
            update_camera=False,
        )

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.world_state,
                elapsed_ms=float(tick.spawn_timeline_ms),
                rng_marks=dict(tick.rng_marks),
                deaths=step.events.deaths,
                events=step.events,
                command_hash=str(step.command_hash),
            ),
        )

    return checkpoints


def test_survival_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.SURVIVAL), ticks=6, seed=0x1234)

    live = _live_survival_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    run_replay(
        replay,
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
    run_replay(
        replay,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.inputs))),
    )

    assert [ck.state_hash for ck in live] == [ck.state_hash for ck in headless]
    assert [ck.command_hash for ck in live] == [ck.command_hash for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]


def test_quest_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.QUESTS), ticks=6, seed=101)
    spawn_entries = _quest_spawn_entries(
        level="1.1",
        player_count=int(replay.header.player_count),
        seed=int(replay.header.seed),
    )

    live = _live_quest_checkpoints(replay, spawn_entries=spawn_entries)
    headless: list[ReplayCheckpoint] = []
    run_replay(
        replay,
        spawn_entries=spawn_entries,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.inputs))),
    )

    assert [ck.state_hash for ck in live] == [ck.state_hash for ck in headless]
    assert [ck.command_hash for ck in live] == [ck.command_hash for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]
