from __future__ import annotations

import inspect
from typing import Any, cast

import crimson.debug_views.arsenal_debug as arsenal_debug_module
import crimson.demo as demo_module
import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.replay.driver.playback_driver as playback_driver_module
import crimson.replay.driver.playback_pump as playback_pump_module
import crimson.replay.driver.replay_benchmark as replay_benchmark_module
import crimson.replay.driver.replay_info as replay_info_module
import crimson.replay.driver.replay_render as replay_render_module
import crimson.sim.batch_apply as batch_apply_module
import crimson.world.audio_bridge as audio_bridge_module
import crimson.world.standalone_tick_harness as standalone_tick_harness_module
from crimson.modes import replay_playback_mode
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.input import PlayerInput
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.world.audio_bridge import AudioBridge
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_session


def test_contract_1_pure_headless_execution_no_render_or_audio_dependencies(mocker) -> None:
    session, _sim_world = make_session()
    ticks = LiveTickSource()
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx", wraps=audio_bridge_module.play_sfx)

    for _ in range(60):
        ticks.poll([PlayerInput(aim=Vec2(512.0, 512.0))])
        step = step_replay_tick(session, ticks.next_tick())
        assert isinstance(step.presentation, DeterministicPresentationPlan)

    assert play_sfx.call_count == 0


def test_contract_5_plan_vs_apply_isolation_for_audio_and_render_side_effects(mocker) -> None:
    session, _sim_world = make_session()
    ticks = LiveTickSource()
    ticks.poll([PlayerInput()])
    audio_bridge = AudioBridge(
        audio=cast(Any, object()),  # sentinel; play_sfx is patched
        audio_rng=Crand(0xBEEF),
    )
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    draw_text = mocker.patch.object(rl, "draw_text")

    plan = step_replay_tick(session, ticks.next_tick()).presentation
    # No audio or rendering happened during deterministic step
    assert play_sfx.call_count == 0
    assert draw_text.call_count == 0

    # SFX only materialize when the presentation plan is explicitly applied
    audio_bridge.apply_plan(plan=plan, apply_audio=True)
    assert [call.args[1] for call in play_sfx.call_args_list] == sfx_ids(plan.sfx)


def test_contract_6_state_apply_and_presentation_apply_stay_separate() -> None:
    state_source = inspect.getsource(batch_apply_module.apply_tick_to_sim)
    output_source = inspect.getsource(batch_apply_module.apply_presentation_plans)

    assert "update_camera" not in state_source
    assert "apply_step_metadata" not in output_source
    assert output_source.count("sync_audio_bridge_state()") == 1
    assert "runtime.audio_bridge.apply_plan" in output_source
    assert "runtime.render_resources.consume_terrain_fx_batch" in output_source


def test_contract_7_every_runner_steps_recorded_ticks() -> None:
    """Live play, harness screens and replays advance only through `step_replay_tick`."""

    gameplay_source = inspect.getsource(base_gameplay_mode_module.BaseGameplayMode._run_deterministic_session_ticks)
    harness_source = inspect.getsource(standalone_tick_harness_module.StandaloneTickHarness.advance_frame)
    replay_source = inspect.getsource(playback_driver_module.PlaybackDriver.step_session)
    demo_source = inspect.getsource(demo_module.DemoView._update_world)
    debug_source = inspect.getsource(arsenal_debug_module.ArsenalDebugView.update)

    for source in (gameplay_source, harness_source, replay_source):
        assert "step_replay_tick(" in source
        assert ".step_tick(" not in source
    # Live play records a tick before the simulation steps it.
    assert gameplay_source.index("recorder.record(tick)") < gameplay_source.index("step_replay_tick(session, tick)")
    assert "self._tick_harness.advance_frame(" in demo_source
    assert "self._tick_harness.advance_frame(" in debug_source


def test_contract_8_replay_frame_advancement_uses_shared_helper() -> None:
    helper_source = inspect.getsource(playback_pump_module.advance_playback_frame)
    replay_source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode._advance_runner)

    assert "driver.step_tick(" in helper_source
    assert "apply_tick_to_sim(" in helper_source
    assert "advance_playback_frame(" in replay_source
    assert "driver.step_tick(" not in replay_source
    assert "apply_tick_to_sim(" not in replay_source


def test_contract_10_replay_driver_walk_is_canonical_loop_owner() -> None:
    walk_source = inspect.getsource(playback_driver_module.PlaybackDriver.walk_ticks)
    run_source = inspect.getsource(playback_driver_module.PlaybackDriver.run)
    driver_init_source = inspect.getsource(playback_driver_module.PlaybackDriver.__init__)
    replay_info_source = inspect.getsource(replay_info_module.collect_replay_info)
    factory_source = inspect.getsource(playback_driver_module.build_verify_playback_driver)
    replay_pump_source = inspect.getsource(playback_pump_module.advance_playback_frame)
    replay_mode_open_source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode.open)
    replay_mode_source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode._advance_runner)
    replay_render_source = inspect.getsource(replay_render_module.run_replay_render_video)
    replay_benchmark_source = inspect.getsource(replay_benchmark_module.run_replay_benchmark)
    replay_render_benchmark_once_source = inspect.getsource(replay_benchmark_module._run_render_once)

    assert "self.step_tick(" in walk_source
    assert "self.walk_ticks(" in run_source
    assert "PlaybackDriverConfig" not in driver_init_source
    assert "PlaybackDriverOptions" not in driver_init_source
    assert "driver.walk_ticks(" in replay_info_source
    assert "driver.step_tick(" not in replay_info_source
    assert "PlaybackDriver(" in factory_source
    assert "PlaybackTickOutcome" not in replay_pump_source
    assert "build_runtime_playback_driver(" in replay_mode_open_source
    assert "PlaybackDriver(" not in replay_mode_open_source
    assert "survival_session" not in replay_mode_open_source
    assert "rush_session" not in replay_mode_open_source
    assert "quest_session" not in replay_mode_open_source
    assert "driver.session.game_tune_started" in replay_mode_source
    assert "hasattr(" not in replay_mode_source
    assert "build_verify_playback_driver(" in replay_render_source
    assert "PlaybackDriver(" not in replay_render_source
    assert "build_verify_playback_driver(" in replay_benchmark_source
    assert "PlaybackDriver(" not in replay_benchmark_source
    assert "tick_progress_callback" not in replay_render_benchmark_once_source
    assert "observer.progress(" in replay_render_benchmark_once_source
