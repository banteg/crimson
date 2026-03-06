from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
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
from crimson.replay.driver.playback_driver import resolve_quest_level_from_replay
from crimson.replay.driver.setup import status_from_snapshot
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import (
    DeterministicSession,
    QuestSpawnState,
    RushSpawnState,
    quest_post_step,
    rush_input_transform,
    rush_mid_step,
)
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.replay_runner_helpers import _run_verify_playback
from tests.world_runtime import WorldRuntimeHost


def _checkpoint_state_projection(checkpoint: ReplayCheckpoint) -> dict[str, object]:
    obj = msgspec.to_builtins(checkpoint)
    for key in ("elapsed_ms", "rng_state", "rng_marks", "deaths", "perk", "events"):
        obj.pop(key, None)
    return obj


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
    packed_tick = replay.ticks[int(tick_index)].inputs
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


def _enforce_rush_loadout(world: WorldRuntimeHost) -> None:
    for player in world.sim_world.players:
        if player.weapon.weapon_id != WeaponId.ASSAULT_RIFLE:
            weapon_assign_player(player, WeaponId.ASSAULT_RIFLE, state=world.sim_world.state)
        player.weapon.ammo = 30.0


def _live_survival_checkpoints(replay: Replay) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.sim_world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt = 1.0 / float(replay.header.tick_rate)

    for tick_index in range(len(replay.ticks)):
        tick = world.step_survival_frame(
            dt,
            inputs=_inputs_for_tick(replay, tick_index),
            auto_pick_perks=False,
            perk_progression_enabled=True,
            defer_camera_shake_update=True,
            apply_audio=False,
        )

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.sim_world.world_state,
                elapsed_ms=float(tick.elapsed_ms),
                rng_marks=dict(tick.rng_marks),
                deaths=tick.step.events.deaths,
                events=tick.step.events,
            ),
        )

    return checkpoints


def _live_rush_checkpoints(replay: Replay) -> list[ReplayCheckpoint]:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.sim_world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )

    spawn = RushSpawnState()
    session = DeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        fx_queue=world.render_resources.fx_queue,
        fx_queue_rotated=world.render_resources.fx_queue_rotated,
        game_mode=GameMode.RUSH,
        perk_progression_enabled=False,
        detail_preset=5,
        gore_disabled=0,
        clear_fx_queues_each_tick=True,
        mid_step_hook=lambda ctx: rush_mid_step(ctx, spawn),
        before_step_hook=lambda: _enforce_rush_loadout(world),
        input_transform=rush_input_transform,
        elapsed_uses_raw_dt=True,
        finalize_post_render_lifecycle=True,
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt = 1.0 / float(replay.header.tick_rate)
    for tick_index in range(len(replay.ticks)):
        tick_inputs = _inputs_for_tick(replay, tick_index)
        timing = session.timing_for_dt(float(dt))
        tick = session.step_tick(
            timing=timing,
            inputs=tick_inputs,
            trace_rng=False,
        )
        step = tick.step
        world.sim_world.apply_step_metadata(
            events=step.events,
            presentation=step.presentation,
            dt_sim=float(step.dt_sim),
            game_tune_started=bool(session.game_tune_started),
        )
        world.sync_audio_bridge_state()
        world.audio_bridge.apply_plan(plan=step.presentation, apply_audio=False)
        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.sim_world.world_state,
                elapsed_ms=float(tick.elapsed_ms),
                rng_marks=dict(tick.rng_marks),
                deaths=step.events.deaths,
                events=step.events,
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
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    world.reset(seed=int(replay.header.seed), player_count=int(replay.header.player_count))
    world.sim_world.state.status = status_from_snapshot(
        quest_unlock_index=int(replay.header.status.quest_unlock_index),
        quest_unlock_index_full=int(replay.header.status.quest_unlock_index_full),
        weapon_usage_counts=replay.header.status.weapon_usage_counts,
    )
    quest_level = resolve_quest_level_from_replay(replay)
    quest = quest_by_level(quest_level) if quest_level else None
    if quest is not None:
        world.sim_world.state.quest_stage_major = int(quest.level_key[0])
        world.sim_world.state.quest_stage_minor = int(quest.level_key[1])
    weapon_id = quest.start_weapon_id if quest is not None else WeaponId.PISTOL
    for player in world.sim_world.players:
        weapon_assign_player(player, weapon_id, state=world.sim_world.state)

    quest_spawn_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
    session = DeterministicSession(
        world=world.sim_world.world_state,
        world_size=float(world.world_size),
        damage_scale_by_type=world.sim_world.damage_scale_by_type,
        fx_queue=world.render_resources.fx_queue,
        fx_queue_rotated=world.render_resources.fx_queue_rotated,
        game_mode=GameMode.QUESTS,
        perk_progression_enabled=True,
        detail_preset=5,
        gore_disabled=0,
        clear_fx_queues_each_tick=True,
        finalize_post_render_lifecycle=True,
        post_step_hook=lambda ctx: quest_post_step(ctx, quest_spawn_state),
    )

    checkpoints: list[ReplayCheckpoint] = []
    dt = 1.0 / float(replay.header.tick_rate)

    for tick_index in range(len(replay.ticks)):
        timing = session.timing_for_dt(float(dt))
        tick = session.step_tick(
            timing=timing,
            inputs=_inputs_for_tick(replay, tick_index),
            trace_rng=False,
        )
        step = tick.step

        world.sim_world.apply_step_metadata(
            events=step.events,
            presentation=step.presentation,
            dt_sim=float(step.dt_sim),
            game_tune_started=False,
        )
        world.sync_audio_bridge_state()
        world.audio_bridge.apply_plan(plan=step.presentation, apply_audio=False)

        checkpoints.append(
            build_checkpoint(
                tick_index=int(tick_index),
                world=world.sim_world.world_state,
                elapsed_ms=float(quest_spawn_state.spawn_timeline_ms),
                rng_marks=dict(tick.rng_marks),
                deaths=step.events.deaths,
                events=step.events,
            ),
        )

    return checkpoints


def test_survival_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.SURVIVAL), ticks=6, seed=0x1234)

    live = _live_survival_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    _run_verify_playback(
        replay,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]


def test_rush_live_vs_headless_tick_pipeline() -> None:
    replay = _build_replay(mode=int(GameMode.RUSH), ticks=6, seed=0x5678)

    live = _live_rush_checkpoints(replay)
    headless: list[ReplayCheckpoint] = []
    _run_verify_playback(
        replay,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
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
    _run_verify_playback(
        replay,
        spawn_entries=spawn_entries,
        checkpoints_out=headless,
        checkpoint_ticks=set(range(len(replay.ticks))),
    )

    assert [_checkpoint_state_projection(ck) for ck in live] == [_checkpoint_state_projection(ck) for ck in headless]
    assert [ck.rng_state for ck in live] == [ck.rng_state for ck in headless]
