from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.modes.base_gameplay_mode as base_gameplay_mode
from crimson.game_world import GameWorld
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.relay_protocol import RoomStart
from crimson.net.rollback_runtime import RollbackRuntime, RollbackRuntimeConfig
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import QuestDeterministicSession
from crimson.sim.timing import FrameTiming
from grim.config import ensure_crimson_cfg
from grim.console import create_console, register_core_cvars
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.view import ViewContext


def test_game_world_init_honors_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2

    world = GameWorld(assets_dir=assets_dir, config=cfg)
    assert [player.index for player in world.players] == [0, 1]


def test_game_world_reset_spreads_player_spawn_positions() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    world = GameWorld(assets_dir=assets_dir)
    world.reset(seed=0xBEEF, player_count=4)

    positions = {(round(player.pos.x, 3), round(player.pos.y, 3)) for player in world.players}
    assert len(positions) == 4


def test_survival_mode_uses_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 2
    ctx = ViewContext(assets_dir=assets_dir)

    mode = SurvivalMode(ctx, config=cfg)
    assert len(mode.world.players) == 2  # intentional: wiring smoke test


def test_quest_mode_update_uses_per_player_input_frame(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.data["player_count"] = 3
    ctx = ViewContext(assets_dir=assets_dir)
    mode = QuestMode(ctx, config=cfg)

    inputs = [PlayerInput(move=Vec2(float(idx), 0.0)) for idx in range(len(mode.world.players))]
    step_result = SimpleNamespace(
        step=SimpleNamespace(),
        spawn_timeline_ms=0.0,
        no_creatures_timer_ms=0.0,
        completion_transition_ms=-1.0,
        play_hit_sfx=False,
        play_completion_music=False,
        completed=False,
    )
    step_tick = mocker.Mock(return_value=step_result)

    class _FakeSession:
        def __init__(self) -> None:
            self.detail_preset = 5
            self.fx_toggle = 0
            self.spawn_entries = ()
            self.spawn_timeline_ms = 0.0
            self.no_creatures_timer_ms = 0.0
            self.completion_transition_ms = -1.0
            self.game_tune_started = False

        def timing_for_dt(self, dt: float) -> FrameTiming:
            return FrameTiming.compute(
                float(dt),
                time_scale_active_entry=False,
                time_scale_factor=1.0,
                zero_gate_active=False,
            )

        def step_tick(self, *, timing, inputs, trace_rng=False):
            return step_tick(timing=timing, inputs=inputs, trace_rng=trace_rng)

    mode._sim_session = cast(QuestDeterministicSession, _FakeSession())
    mocker.patch.object(mode, "_update_audio", side_effect=lambda _dt: None)
    mocker.patch.object(mode, "_tick_frame", side_effect=lambda _dt: (0.02, 20.0))
    mocker.patch.object(mode, "_handle_input", side_effect=lambda: None)
    mocker.patch.object(mode, "_build_local_inputs", side_effect=lambda *, dt: inputs)
    mocker.patch.object(mode, "_death_transition_ready", side_effect=lambda: False)
    mocker.patch.object(GameWorld, "apply_step_result", side_effect=lambda *_args, **_kwargs: None)

    mode.update(0.02)

    step_tick.assert_called_once()
    assert step_tick.call_args.kwargs["inputs"] is inputs
    assert len(inputs) == 3


def test_base_gameplay_build_local_inputs_passes_creatures(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = SurvivalMode(ctx, config=cfg)
    build_frame_inputs = mocker.patch.object(
        mode._local_input,
        "build_frame_inputs",
        side_effect=lambda *, players, **_kwargs: [PlayerInput() for _ in players],
    )

    frame = mode._build_local_inputs(dt=0.016)

    assert len(frame) == len(mode.world.players)
    build_frame_inputs.assert_called_once()
    assert build_frame_inputs.call_args.kwargs["creatures"] is mode.creatures.entries
    assert bool(mode._local_input._preserve_bugs) == bool(mode.state.preserve_bugs)


def test_rush_mode_pauses_sim_while_lan_wait_gate_is_active(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg)
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )

    class _FakeClock:
        def __init__(self) -> None:
            self.reset_calls = 0
            self.advance_calls = 0
            self.dt_tick = 1.0 / 60.0

        def reset(self) -> None:
            self.reset_calls += 1

        def advance(self, _dt: float) -> int:
            self.advance_calls += 1
            return 1

    clock = _FakeClock()
    mode._sim_clock = clock

    mocker.patch.object(mode, "_update_audio", side_effect=lambda _dt: None)
    mocker.patch.object(mode, "_tick_frame", side_effect=lambda _dt: (0.02, 20.0))
    mocker.patch.object(mode, "_handle_input", side_effect=lambda: None)

    mode.update(0.02)

    assert clock.reset_calls == 1
    assert clock.advance_calls == 0


def test_rush_mode_debug_f10_releases_lan_wait_gate(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg)
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=2,
        connected_players=1,
        waiting_for_players=True,
    )

    class _FakeClock:
        def __init__(self) -> None:
            self.reset_calls = 0
            self.advance_calls = 0
            self.dt_tick = 1.0 / 60.0

        def reset(self) -> None:
            self.reset_calls += 1

        def advance(self, _dt: float) -> int:
            self.advance_calls += 1
            return 0

    clock = _FakeClock()
    mode._sim_clock = clock

    mocker.patch.object(mode, "_update_audio", side_effect=lambda _dt: None)
    mocker.patch.object(mode, "_tick_frame", side_effect=lambda _dt: (0.02, 20.0))
    mocker.patch.object(mode, "_handle_input", side_effect=lambda: None)
    mocker.patch.object(base_gameplay_mode, "debug_enabled", side_effect=lambda: True)
    mocker.patch.object(
        base_gameplay_mode.rl,
        "is_key_pressed",
        side_effect=lambda key: key == rl.KeyboardKey.KEY_F10,
    )

    mode.update(0.02)

    assert clock.advance_calls == 1
    assert mode._lan_wait_gate_active() is False


def test_lan_player_rings_follow_lan_state_and_cvar(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    console = create_console(tmp_path, assets_dir=assets_dir)
    register_core_cvars(console, width=1024, height=768)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg, console=console)
    runtime = RollbackRuntime(
        RollbackRuntimeConfig(
            role="join",
            mode_id=1,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=32000,
        ),
    )
    runtime.match_start_event = RoomStart(slot_index=2)
    mode.bind_lan_runtime(runtime)

    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )
    assert mode.world.lan_player_rings_enabled is False
    assert mode.world.lan_local_aim_indicators_only is True
    assert mode.world.lan_local_player_slot_index == 2

    console.exec_line("cv_lanPlayerRings 1")
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )
    assert mode.world.lan_player_rings_enabled is True

    mode.set_lan_runtime(
        enabled=False,
        role="",
        expected_players=1,
        connected_players=1,
        waiting_for_players=False,
    )
    assert mode.world.lan_player_rings_enabled is False
    assert mode.world.lan_local_aim_indicators_only is False
