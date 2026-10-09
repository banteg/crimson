from __future__ import annotations

from pathlib import Path

import crimson.replay.driver.playback_pump as playback_pump_module
import crimson.world.audio_bridge as audio_bridge_module
from crimson.game_modes import GameMode
from crimson.replay.driver.playback_driver import build_runtime_playback_driver
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.clock import FixedStepClock
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.run_spec import RunSpec
from crimson.sim.sessions import DeterministicSession
from crimson.world import WorldRuntime
from crimson.world.standalone_tick_harness import StandaloneTickHarness
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from tests.support.audio import sfx_ids
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import idle_replay


def test_contract_6_state_apply_and_presentation_apply_stay_separate(mocker, tmp_path: Path) -> None:
    audio = AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=False, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=False, volume=1.0, rng=Crand(0x1234)),
    )
    runtime = WorldRuntime(assets_dir=tmp_path, audio_rng=Crand(0xBEEF), audio=audio)
    runtime.world.players[0].weapon.shot_cooldown = 0.0
    session = DeterministicSession.start(
        world=runtime.world,
        perk_progression_enabled=False,
    )
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    sync_audio = mocker.spy(runtime, "sync_audio_bridge_state")
    ticks = LiveTickSource()
    plans: list[DeterministicPresentationPlan] = []
    for _ in range(2):
        ticks.poll([player_input(aim=Vec2(700.0, 512.0), fire_down=True, fire_pressed=True)])
        step = step_replay_tick(session, ticks.next_tick())
        camera = runtime.camera
        runtime.presentation.advance(step.dt_sim)
        # Advancing the presentation clock applies no presentation output.
        assert runtime.camera == camera
        assert play_sfx.call_count == 0
        plans.append(step.presentation)
    clock = (runtime.presentation.elapsed_ms, runtime.presentation.bonus_anim_phase)
    assert clock[0] > 0.0

    apply_presentation_plans(plans=plans, runtime=runtime)

    # Presentation output does not touch the presentation clock, syncs audio
    # once per batch, and plays each plan's sounds in tick order.
    assert (runtime.presentation.elapsed_ms, runtime.presentation.bonus_anim_phase) == clock
    assert sync_audio.call_count == 1
    expected_sfx = [sfx for plan in plans for sfx in (*sfx_ids(plan.sfx), *sfx_ids(plan.post_apply_sfx))]
    assert expected_sfx
    assert [call.args[1] for call in play_sfx.call_args_list] == expected_sfx


def test_contract_8_live_and_replay_frames_advance_the_presentation_clock_alike(tmp_path: Path) -> None:
    live_runtime = WorldRuntime(assets_dir=tmp_path, audio_rng=Crand(0))
    harness = StandaloneTickHarness(game_mode=GameMode.SURVIVAL, frame_inputs=lambda _dt: [player_input()])

    replay = idle_replay(16, run=RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0))
    driver = build_runtime_playback_driver(replay, max_ticks=None)
    replay_runtime = WorldRuntime(assets_dir=tmp_path, audio_rng=Crand(0))
    replay_runtime.start_session(driver.session)
    replay_clock = FixedStepClock(tick_rate=60)

    next_tick = 0
    for frame_dt in (1.0 / 60.0, 2.5 / 60.0, 0.25 / 60.0, 3.0 / 60.0):
        live_ticks = harness.advance_frame(live_runtime, frame_dt)
        advance = playback_pump_module.advance_playback_frame(
            driver=driver,
            runtime=replay_runtime,
            clock=replay_clock,
            start_tick=next_tick,
            dt_seconds=frame_dt,
            max_ticks=None,
            tick_limit=len(replay.ticks),
        )
        next_tick = advance.next_tick_index

        assert len(advance.tick_results) == live_ticks
        assert replay_runtime.presentation.elapsed_ms == live_runtime.presentation.elapsed_ms
        assert replay_runtime.presentation.bonus_anim_phase == live_runtime.presentation.bonus_anim_phase
    assert next_tick > 0
