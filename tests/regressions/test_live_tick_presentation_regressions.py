from __future__ import annotations

from pathlib import Path

from crimson.creatures.spawn import SpawnId
from crimson.game_modes import GameMode
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import DeterministicSession
from crimson.weapons import build_damage_scale_by_type
from tests.support.world_runtime import WorldRuntimeHost


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_live_tick_path_projectile_hits_enqueue_decals() -> None:
    runtime = WorldRuntimeHost(assets_dir=_assets_dir())
    player = runtime.world.players[0]
    target = player.pos.offset(dx=48.0)
    runtime.world.creatures.spawn_template(
        SpawnId.ZOMBIE_SMALL_WHITE_42,
        target,
        3.14,
        runtime.world.state.rng,
    )
    session = DeterministicSession(
        world=runtime.world,
        world_size=float(runtime.world_size),
        damage_scale_by_type=build_damage_scale_by_type(),
        game_mode=GameMode.SURVIVAL,
        detail_preset=5,
        violence_disabled=0,
        game_tune_started=bool(runtime.game_tune_started),
        demo_mode_active=False,
        perk_progression_enabled=False,
        apply_world_dt_steps=True,
    )
    ticks = LiveTickSource()

    for _ in range(120):
        ticks.poll([PlayerInput(aim=target, fire_down=True, fire_pressed=True)])
        step = step_replay_tick(session, ticks.next_tick())
        if not step.presentation.terrain_fx.is_empty():
            break
        runtime.advance_presentation_clock(dt_sim=step.dt_sim, game_tune_started=bool(session.game_tune_started))
        runtime.sync_audio_bridge_state()
        runtime.audio_bridge.apply_plan(plan=step.presentation, apply_audio=True)
        runtime.update_camera(step.presentation.camera)

    assert not step.presentation.terrain_fx.is_empty()
