from __future__ import annotations

import inspect
from pathlib import Path

import crimson.audio_router as audio_router_module
import crimson.debug_views.arsenal_debug as arsenal_debug_module
import crimson.demo as demo_module
import crimson.modes.base_gameplay_mode as base_gameplay_mode_module
import crimson.modes.replay_playback_mode as replay_playback_mode
import crimson.replay.driver.playback_driver as playback_driver_module
import crimson.replay.driver.playback_pump as playback_pump_module
import crimson.replay.driver.replay_benchmark as replay_benchmark_module
import crimson.replay.driver.replay_info as replay_info_module
import crimson.replay.driver.replay_render as replay_render_module
import crimson.sim.batch_apply as batch_apply_module
import crimson.sim.frame_pump as frame_pump_module
import crimson.sim.presentation_reactions as presentation_reactions_module
import crimson.world.standalone_tick_harness as standalone_tick_harness_module
from crimson.game_modes import GameMode
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay_file
from crimson.sim.clock import FixedStepClock
from crimson.sim.frame_pump import advance_tick_runner_frame
from crimson.sim.hooks import TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    GameCommand,
    InputProvider,
    InputStatus,
    LocalInputProvider,
    PerkPickCommand,
    ResolvedTick,
    TickSupply,
)
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.sessions import DeterministicSession, DeterministicSessionTick
from crimson.sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig
from crimson.world.audio_bridge import AudioBridge
from crimson.world.render_resources import RenderResources
from crimson.world.terrain_runtime import TerrainRuntime
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext
from tests.support.builders.input_providers import StaticLocalInputRuntime
from tests.support.builders.session import make_session


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


class _MockLockstepRuntime:
    def __init__(self) -> None:
        self._pending_commands: list[GameCommand] = []
        self._commands_by_peer_and_tick: dict[str, dict[int, list[GameCommand]]] = {
            "host": {},
            "client": {},
        }

    def submit_local_command(self, command: GameCommand) -> None:
        self._pending_commands.append(command)

    def pull_commands(self, *, peer: str, tick_index: int) -> list[GameCommand]:
        tick = int(tick_index)
        if tick not in self._commands_by_peer_and_tick["host"] and self._pending_commands:
            commands = list(self._pending_commands)
            self._pending_commands.clear()
            for target in self._commands_by_peer_and_tick:
                self._commands_by_peer_and_tick[target][tick] = list(commands)
        return list(self._commands_by_peer_and_tick[str(peer)].pop(int(tick_index), []))


class _LockstepInputProvider(InputProvider):
    def __init__(
        self,
        *,
        runtime: _MockLockstepRuntime,
        peer: str,
        inputs: tuple[PlayerInput, ...],
        accepts_local_commands: bool = False,
    ) -> None:
        self._runtime = runtime
        self._peer = peer
        self._inputs = inputs
        self._accepts_local_commands = accepts_local_commands

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        tick = int(tick_index)
        return TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=tick,
                dt_seconds=float(default_dt_seconds),
                inputs=tuple(self._inputs),
                commands=tuple(self._runtime.pull_commands(peer=self._peer, tick_index=tick)),
            ),
        )

    def supports_command_submission(self) -> bool:
        return bool(self._accepts_local_commands)

    def submit_command(self, command: GameCommand) -> None:
        if self._accepts_local_commands:
            self._runtime.submit_local_command(command)


def _advance_with_clock(
    *,
    runner: TickRunner,
    clock: FixedStepClock,
    start_tick: int,
    frame_index: int,
    dt_seconds: float,
    max_ticks: int | None = None,
    is_networked: bool = False,
    is_replay: bool = False,
) -> tuple[TickBatchResult, int, int]:
    ticks_requested = int(clock.advance(float(dt_seconds)))
    if max_ticks is not None:
        ticks_requested = min(int(ticks_requested), max(0, int(max_ticks)))
    advance = advance_tick_runner_frame(
        runner=runner,
        start_tick=int(start_tick),
        frame_index=int(frame_index),
        ticks_requested=int(ticks_requested),
        dt_seconds=float(dt_seconds),
        tick_dt_seconds=float(clock.dt_tick),
        is_networked=bool(is_networked),
        is_replay=bool(is_replay),
        refund_clock=clock,
    )
    return advance.batch, int(advance.next_tick_index), int(advance.frame_index)


def test_contract_1_pure_headless_execution_no_render_or_audio_dependencies(mocker) -> None:
    session, sim_world = make_session()
    provider = LocalInputProvider(
        player_count=len(sim_world.players),
        runtime=StaticLocalInputRuntime(inputs=(PlayerInput(aim=Vec2(512.0, 512.0)),)),
    )
    runner = TickRunner(
        session=session,
        input_provider=provider,
        config=TickRunnerConfig(),
    )
    play_sfx = mocker.patch.object(
        audio_router_module,
        "play_sfx",
        wraps=audio_router_module.play_sfx,
    )

    completed: list[object] = []
    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    for _ in range(60):
        batch, next_tick_index, frame_index = _advance_with_clock(
            runner=runner,
            clock=clock,
            start_tick=next_tick_index,
            frame_index=frame_index,
            dt_seconds=1.0 / 60.0,
            max_ticks=1,
        )
        assert batch.ticks_completed == 1
        completed.extend(batch.completed_results)

    assert int(next_tick_index) == 60
    assert len(completed) == 60
    assert play_sfx.call_count == 0
    for result in completed:
        assert isinstance(result, TickResult)
        assert result.payload is not None
        payload = result.payload
        assert isinstance(payload, DeterministicSessionTick)
        assert isinstance(payload.step.presentation, DeterministicPresentationPlan)
        assert payload.step is not None


def test_contract_3_lockstep_command_propagation_over_network_provider() -> None:
    runtime = _MockLockstepRuntime()
    tick_input = (PlayerInput(),)
    host_provider = _LockstepInputProvider(
        runtime=runtime,
        peer="host",
        inputs=tick_input,
        accepts_local_commands=True,
    )
    client_provider = _LockstepInputProvider(
        runtime=runtime,
        peer="client",
        inputs=tick_input,
    )
    host_session, _ = make_session(seed=42)
    client_session, _ = make_session(seed=42)

    host_runner = TickRunner(
        session=host_session,
        input_provider=host_provider,
        config=TickRunnerConfig(),
    )
    client_runner = TickRunner(
        session=client_session,
        input_provider=client_provider,
        config=TickRunnerConfig(),
    )

    command = PerkPickCommand(player_index=0, choice_index=1)
    host_provider.submit_command(command)

    host_clock = FixedStepClock(tick_rate=60)
    host_frame_index = 0
    host_next_tick_index = 0
    host_batch, host_next_tick_index, host_frame_index = _advance_with_clock(
        runner=host_runner,
        clock=host_clock,
        start_tick=host_next_tick_index,
        frame_index=host_frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
        is_networked=True,
    )

    client_clock = FixedStepClock(tick_rate=60)
    client_frame_index = 0
    client_next_tick_index = 0
    client_batch, client_next_tick_index, client_frame_index = _advance_with_clock(
        runner=client_runner,
        clock=client_clock,
        start_tick=client_next_tick_index,
        frame_index=client_frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
        is_networked=True,
    )

    # Commands propagated through runner to both host and client
    assert host_batch.completed_results[0].source_tick.commands == (command,)
    assert client_batch.completed_results[0].source_tick.commands == (command,)


def test_contract_4_live_to_replay_uses_survival_session_and_matches_ticks(
    mocker,
    tmp_path: Path,
) -> None:
    tick_count = 10
    input_row = [PlayerInput(aim=Vec2(512.0, 512.0))]
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
        world_size=1024.0,
        detail_preset=5,
        violence_disabled=0,
    )
    recorder = ReplayRecorder(header)

    live_session, sim_world = make_session(seed=int(header.seed))
    live_provider = LocalInputProvider(
        player_count=1,
        runtime=StaticLocalInputRuntime(inputs=tuple(input_row)),
    )
    live_runner = TickRunner(
        session=live_session,
        input_provider=live_provider,
        config=TickRunnerConfig(),
    )
    live_clock = FixedStepClock(tick_rate=int(header.tick_rate))
    live_frame_index = 0
    live_next_tick_index = 0

    live_tick_indices: list[int] = []
    for _ in range(int(tick_count)):
        recorder.record_tick(list(input_row))
        batch, live_next_tick_index, live_frame_index = _advance_with_clock(
            runner=live_runner,
            clock=live_clock,
            start_tick=live_next_tick_index,
            frame_index=live_frame_index,
            dt_seconds=1.0 / 60.0,
            max_ticks=1,
        )
        assert batch.ticks_completed == 1
        live_tick_indices.append(int(batch.completed_results[0].source_tick.tick_index))

    replay = recorder.finish()
    replay_path = tmp_path / "contract_live_to_replay.crd"
    dump_replay_file(replay_path, replay)

    cfg = ensure_crimson_cfg(tmp_path)
    console = create_console(tmp_path, assets_dir=_assets_dir())
    mode = replay_playback_mode.ReplayPlaybackMode(
        ViewContext(assets_dir=_assets_dir()),
        replay_path=replay_path,
        config=cfg,
        console=console,
        max_ticks=tick_count,
    )

    mocker.patch.object(replay_playback_mode, "load_small_font", return_value=None)
    mocker.patch.object(replay_playback_mode, "init_audio_state", return_value=None)

    # WorldRuntime is created inside open(); stub it to avoid GPU/resource
    # initialisation while still exposing a real SimWorldState for the
    # deterministic hash comparison that follows.
    _real_cls = replay_playback_mode.WorldRuntime

    class _StubRuntime:
        def __init__(self, **kwargs: object) -> None:
            self._inner = _real_cls.__new__(_real_cls)
            # Only materialise the sim_world so the hash contract can run.
            from crimson.world.sim_world_state import SimWorldState as _SWS

            sw = _SWS(
                world_size=float(kwargs.get("world_size", 1024.0)),  # type: ignore[arg-type]
                demo_mode_active=bool(kwargs.get("demo_mode_active", False)),
                hardcore=bool(kwargs.get("hardcore", False)),
                quest_fail_retry_count=int(kwargs.get("quest_fail_retry_count", 0)),  # type: ignore[arg-type]
                preserve_bugs=bool(kwargs.get("preserve_bugs", False)),
            )
            self.sim_world = sw
            self.render_resources = RenderResources(assets_dir=_assets_dir())
            self.terrain_runtime = mocker.Mock(spec=TerrainRuntime)
            self.audio_bridge = AudioBridge(audio_rng=kwargs.get("audio_rng", Crand(0xBEEF)))  # type: ignore[arg-type]
            self.camera = Vec2(-1.0, -1.0)

        def reset(self, *, seed: int, player_count: int, **_kw: object) -> None:
            self.sim_world.reset(seed=int(seed), player_count=int(player_count))

        def open_runtime(self) -> None:
            pass

        def close_runtime(self) -> None:
            pass

        def sync_audio_bridge_state(self) -> None:
            pass

        def update_camera(self, _dt: float) -> None:
            pass

    mocker.patch.object(replay_playback_mode, "WorldRuntime", _StubRuntime)

    mode.open()
    assert mode._driver is not None
    assert isinstance(mode._driver.session, DeterministicSession)

    replay_tick_indices: list[int] = []

    def _apply_presentation_outputs(*, outputs, apply_runtime, **_kwargs) -> None:
        for output in outputs:
            replay_tick_indices.append(int(output.tick_index))
            apply_runtime.output_applied(output)

    mocker.patch.object(
        replay_playback_mode,
        "apply_presentation_outputs",
        side_effect=_apply_presentation_outputs,
    )
    for _ in range(int(tick_count)):
        mode._advance_runner(
            dt_seconds=float(mode._dt),
            max_ticks=1,
        )

    assert replay_tick_indices == live_tick_indices
    mode.close()


def test_contract_5_plan_vs_apply_isolation_for_audio_and_render_side_effects(mocker) -> None:
    session, sim_world = make_session()

    provider = LocalInputProvider(
        player_count=1,
        runtime=StaticLocalInputRuntime(inputs=(PlayerInput(),)),
    )
    runner = TickRunner(
        session=session,
        input_provider=provider,
        config=TickRunnerConfig(),
    )

    audio_bridge = AudioBridge(
        demo_mode_active=False,
        reflex_boost_timer_source=lambda: 0.0,
        audio=object(),  # type: ignore[arg-type]  # sentinel; play_sfx is patched
        audio_rng=Crand(0xBEEF),
    )
    play_sfx = mocker.patch.object(audio_router_module, "play_sfx")
    draw_text = mocker.patch.object(rl, "draw_text")

    clock = FixedStepClock(tick_rate=60)
    frame_index = 0
    next_tick_index = 0
    batch, next_tick_index, frame_index = _advance_with_clock(
        runner=runner,
        clock=clock,
        start_tick=next_tick_index,
        frame_index=frame_index,
        dt_seconds=1.0 / 60.0,
        max_ticks=1,
    )
    assert batch.ticks_completed == 1
    # No audio or rendering happened during deterministic step
    assert play_sfx.call_count == 0
    assert draw_text.call_count == 0

    payload = batch.completed_results[0].payload
    assert isinstance(payload, DeterministicSessionTick)
    plan = payload.step.presentation

    # SFX only materialize when the presentation plan is explicitly applied
    audio_bridge.apply_plan(plan=plan, apply_audio=True)
    sfx_played = [call.args[1] for call in play_sfx.call_args_list]
    assert sfx_played == list(plan.sfx)


def test_contract_6_shared_batch_apply_separates_deterministic_and_output_phases() -> None:
    deterministic_batch_source = inspect.getsource(batch_apply_module.apply_sim_metadata_batch)
    deterministic_tick_source = inspect.getsource(batch_apply_module.apply_sim_metadata_tick_result)
    deterministic_apply_source = inspect.getsource(batch_apply_module.apply_tick_to_sim)
    output_source = inspect.getsource(batch_apply_module.apply_presentation_outputs)

    assert "update_camera" not in deterministic_batch_source
    assert "update_camera" not in deterministic_tick_source
    assert "update_camera" not in deterministic_apply_source
    assert "apply_step_metadata" not in output_source
    assert output_source.count("sync_audio_bridge_state()") == 1
    assert "runtime.audio_bridge.apply_plan" in output_source
    assert "runtime.render_resources.consume_terrain_fx_batch" in output_source


def test_contract_7_live_frame_advancement_uses_shared_helper() -> None:
    helper_source = inspect.getsource(frame_pump_module.advance_tick_runner_frame)
    gameplay_source = inspect.getsource(base_gameplay_mode_module.BaseGameplayMode._run_deterministic_session_ticks)
    lan_source = inspect.getsource(base_gameplay_mode_module.BaseGameplayMode._consume_lan_tick_frames)
    harness_source = inspect.getsource(standalone_tick_harness_module.StandaloneTickHarness.advance_frame)
    demo_source = inspect.getsource(demo_module.DemoView._update_world)
    debug_source = inspect.getsource(arsenal_debug_module.ArsenalDebugView.update)

    assert "runner.begin_frame(" in helper_source
    assert "runner.advance_ticks(" in helper_source
    assert "refund_clock.accum +=" in helper_source
    assert "advance_tick_runner_frame(" in gameplay_source
    assert "advance_tick_runner_frame(" in lan_source
    assert "runner.begin_frame(" not in gameplay_source
    assert "runner.advance_ticks(" not in gameplay_source
    assert "runner.begin_frame(" not in lan_source
    assert "runner.advance_ticks(" not in lan_source
    assert "advance_tick_runner_frame(" in harness_source
    assert "runner.begin_frame(" not in harness_source
    assert "runner.advance_ticks(" not in harness_source
    assert "self._tick_harness.advance_frame(" in demo_source
    assert "self._tick_harness.advance_frame(" in debug_source


def test_contract_8_replay_frame_advancement_uses_shared_helper() -> None:
    helper_source = inspect.getsource(playback_pump_module.advance_playback_frame)
    replay_source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode._advance_runner)

    assert "advance_tick_runner_frame(" in helper_source
    assert "apply_tick_to_sim(" in helper_source
    assert "_PlaybackStepRunner(" in helper_source
    assert "advance_playback_frame(" in replay_source
    assert "driver.step_tick(" not in replay_source
    assert "apply_tick_to_sim(" not in replay_source
    assert "advance_tick_runner_frame(" not in replay_source


def test_contract_9_post_apply_reactions_are_shared() -> None:
    helper_source = inspect.getsource(presentation_reactions_module.apply_post_apply_reaction)
    gameplay_source = inspect.getsource(base_gameplay_mode_module.BaseGameplayMode._process_tick_batch_results)
    replay_source = inspect.getsource(replay_playback_mode.ReplayPlaybackMode._apply_post_apply_reaction)
    world_source = inspect.getsource(standalone_tick_harness_module._StandalonePresentationApplyRuntime.output_applied)

    assert 'runtime.play_sfx(SfxId.QUESTHIT)' in helper_source
    assert "PerkPickCommand" not in gameplay_source
    assert 'play_sfx(SfxId.UI_BONUS)' not in gameplay_source
    assert "apply_post_apply_reaction(" in replay_source
    assert "apply_post_apply_reaction(" in world_source


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
