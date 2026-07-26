from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import crimson.modes.quest_mode as quest_mode_module
from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.net.relay_protocol import RoomStart
from crimson.net.rollback_runtime import JoinRollbackRuntimeConfig, RollbackRuntime
from crimson.quests.level import QuestLevel
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import DeterministicSession
from grim.assets import RuntimeResources, TextureId, register_runtime_resources
from grim.config import ensure_crimson_cfg
from grim.console import create_console, register_core_cvars
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext
from tests.support.world_runtime import WorldRuntimeHost


def _register_runtime_resources_stub(assets_dir: Path) -> None:
    tex = cast("rl.Texture", SimpleNamespace(width=1, height=1, id=1))
    register_runtime_resources(
        RuntimeResources(
            assets_dir=assets_dir,
            textures={texture_id: tex for texture_id in TextureId},
            small_font=cast(SmallFontData, SimpleNamespace(cell_size=10, widths=[8] * 256)),
        ),
    )


def test_game_world_init_honors_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.gameplay.player_count = 2

    world = WorldRuntimeHost(assets_dir=assets_dir, config=cfg)
    assert [player.index for player in world.sim_world.players] == [0, 1]


def test_game_world_reset_spreads_player_spawn_positions() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    world = WorldRuntimeHost(assets_dir=assets_dir)
    world.reset(seed=0xBEEF, player_count=4)

    positions = {(round(player.pos.x, 3), round(player.pos.y, 3)) for player in world.sim_world.players}
    assert len(positions) == 4


def test_survival_mode_uses_config_player_count(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.gameplay.player_count = 2
    ctx = ViewContext(assets_dir=assets_dir)

    mode = SurvivalMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    assert len(mode.sim_world.players) == 2  # intentional: wiring smoke test


def test_quest_mode_update_uses_per_player_input_frame(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"
    _register_runtime_resources_stub(assets_dir)

    cfg = ensure_crimson_cfg(tmp_path)
    cfg.gameplay.player_count = 3
    ctx = ViewContext(assets_dir=assets_dir)
    mode = QuestMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    mocker.patch.object(quest_mode_module, "load_grim_mono_font", return_value=SimpleNamespace())
    mode.open()
    mocker.patch.object(mode, "_sync_audio_and_ground", return_value=None)
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    mode.start_run(QuestLevel(1, 1), status=None)
    mode.render_resources.ground = None

    step_tick_calls: list[list[PlayerInput]] = []
    original_step_tick = DeterministicSession.step_tick

    def _capture_step_tick(self, *, dt, inputs, trace_rng=False, commands=None):
        step_tick_calls.append(list(inputs))
        return original_step_tick(self, dt=dt, inputs=inputs, trace_rng=trace_rng, commands=commands)

    mocker.patch.object(DeterministicSession, "step_tick", _capture_step_tick)

    inputs = [PlayerInput(move=Vec2(float(idx), 0.0)) for idx in range(len(mode.sim_world.players))]
    mocker.patch.object(mode, "_update_audio", side_effect=lambda _dt: None)
    mocker.patch.object(mode, "_tick_frame", side_effect=lambda _dt: (0.02, 20.0))
    mocker.patch.object(mode, "_handle_input", side_effect=lambda: None)
    mocker.patch.object(mode, "_build_local_inputs", side_effect=lambda *, dt: inputs)
    mocker.patch.object(mode, "_death_transition_ready", side_effect=lambda: False)
    mode.update(0.02)

    assert len(step_tick_calls) == 1
    assert step_tick_calls[0] == inputs
    assert len(inputs) == 3


def test_base_gameplay_build_local_inputs_passes_creatures(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = SurvivalMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    build_frame_inputs = mocker.patch.object(
        mode._local_input,
        "build_frame_inputs",
        side_effect=lambda *, players, **_kwargs: [PlayerInput() for _ in players],
    )

    frame = mode._build_local_inputs(dt=0.016)

    assert len(frame) == len(mode.sim_world.players)
    build_frame_inputs.assert_called_once()
    assert build_frame_inputs.call_args.kwargs["creatures"] is mode.creatures.entries
    assert bool(mode._local_input._preserve_bugs) == bool(mode.state.preserve_bugs)


def test_rush_mode_pauses_sim_while_lan_wait_gate_is_active(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )

    reset_clock = mocker.patch.object(mode, "_reset_gameplay_frame_clock", side_effect=lambda: None)
    run_ticks = mocker.patch.object(mode, "_run_deterministic_session_ticks", return_value=0)
    mocker.patch.object(mode, "_update_audio", side_effect=lambda _dt: None)
    mocker.patch.object(mode, "_tick_frame", side_effect=lambda _dt: (0.02, 20.0))
    mocker.patch.object(mode, "_handle_input", side_effect=lambda: None)

    mode.update(0.02)

    reset_clock.assert_called_once()
    run_ticks.assert_not_called()


def test_rush_mode_debug_f10_does_not_bypass_lan_wait_gate(mocker, tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg, audio_rng=Crand(0xBEEF))
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=2,
        connected_players=1,
        waiting_for_players=True,
    )

    run_ticks = mocker.patch.object(mode, "_run_deterministic_session_ticks", return_value=1)
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

    run_ticks.assert_not_called()
    assert mode._lan_wait_gate_active() is True


def test_lan_player_rings_follow_lan_state_and_cvar(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    console = create_console(tmp_path, assets_dir=assets_dir)
    register_core_cvars(console, width=1024, height=768)
    ctx = ViewContext(assets_dir=assets_dir)
    mode = RushMode(ctx, config=cfg, console=console, audio_rng=Crand(0xBEEF))
    runtime = RollbackRuntime(
        JoinRollbackRuntimeConfig(
            mode_id=GameMode.SURVIVAL,
            player_count=2,
            relay_host="127.0.0.1",
            relay_port=32000,
        ),
    )
    runtime.match_start_event = RoomStart(room_code="ab12", slot_index=2)
    mode.bind_lan_runtime(runtime)

    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )
    assert mode.lan_player_rings_enabled is False
    assert mode.lan_local_aim_indicators_only is True
    assert mode.lan_local_player_slot_index == 2

    console.exec_line("cv_lanPlayerRings 1")
    mode.set_lan_runtime(
        enabled=True,
        role="host",
        expected_players=3,
        connected_players=1,
        waiting_for_players=True,
    )
    assert mode.lan_player_rings_enabled is True

    mode.set_lan_runtime(
        enabled=False,
        role="",
        expected_players=1,
        connected_players=1,
        waiting_for_players=False,
    )
    assert mode.lan_player_rings_enabled is False
    assert mode.lan_local_aim_indicators_only is False
