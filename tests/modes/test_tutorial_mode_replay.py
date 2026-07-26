from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import crimson.modes.tutorial_mode as tutorial_mode_module
import crimson.world.render_resources as render_resources_module
from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.perks import PerkId
from crimson.sim.sessions import DeterministicSession
from grim.rand import Crand
from grim.raylib_api import rl
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_tutorial_constructor_starts_without_placeholder_session(make_mode_config) -> None:
    config = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))
    assert mode._sim_session is None


def test_tutorial_open_creates_session_and_recorder(mocker, make_mode_config) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL, updates={"player_count": 4})
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), config=cfg, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    resources = SimpleNamespace(texture=lambda _texture_id: object())
    small_font = SimpleNamespace(cell_size=10)
    mocker.patch.object(render_resources_module, "runtime_resources_for", return_value=resources)
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=small_font)
    reset_runtime = mocker.patch.object(mode._world_runtime, "reset", wraps=mode._world_runtime.reset)
    mode.open()

    assert int(mode.config.gameplay.player_count) == 4
    assert reset_runtime.call_args.kwargs["player_count"] == 1
    assert isinstance(mode._sim_session, DeterministicSession)
    assert mode._replay_recorder is not None
    assert mode._replay_recorder.header.game_mode_id == GameMode.TUTORIAL
    assert int(mode._replay_recorder.header.player_count) == 1


def test_tutorial_stage6_pick_waits_for_sim_progress_before_reopen(mocker, make_mode_config) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), config=cfg, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    resources = SimpleNamespace(texture=lambda _texture_id: object())
    small_font = SimpleNamespace(cell_size=10, widths=[8] * 256)
    mocker.patch.object(render_resources_module, "runtime_resources_for", return_value=resources)
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=small_font)
    mocker.patch.object(base_gameplay_mode.rl, "get_mouse_position", side_effect=lambda: rl.Vector2(0.0, 0.0))
    mocker.patch.object(base_gameplay_mode.rl, "get_screen_width", side_effect=lambda: 640)
    mocker.patch.object(base_gameplay_mode.rl, "get_screen_height", side_effect=lambda: 480)
    mocker.patch.object(tutorial_mode_module.rl, "is_key_pressed", side_effect=lambda _key: False)
    mocker.patch.object(tutorial_mode_module.rl, "is_mouse_button_pressed", side_effect=lambda _button: False)
    mocker.patch.object(mode, "_update_prompt_buttons", return_value=None)
    mocker.patch.object(mode, "_build_input", return_value=SimpleNamespace())
    mode.open()

    mode.state.tutorial.stage_index = 6
    mode.state.perk_selection.pending_count = 1
    mode.state.perk_selection.choices[:] = [PerkId.GRIM_DEAL]
    mode.state.perk_selection.choices_dirty = False

    open_calls = 0
    original_open_perk_menu = mode._open_perk_menu

    def _counted_open() -> None:
        nonlocal open_calls
        open_calls += 1
        original_open_perk_menu()

    pick_calls = 0

    def _pick_once(_ctx, _choices, *, dt_ui_ms: float) -> int | None:
        nonlocal pick_calls
        _ = dt_ui_ms
        pick_calls += 1
        if pick_calls == 1:
            mode._perk_menu.close()
            return 0
        return None

    session = mode._sim_session
    assert session is not None

    tick_calls = 0

    def _run_ticks(**_kwargs) -> None:
        nonlocal tick_calls
        tick_calls += 1
        if tick_calls >= 2:
            session.elapsed_ms += 1000.0 / 60.0

    mocker.patch.object(mode, "_open_perk_menu", side_effect=_counted_open)
    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_pick_once)
    mocker.patch.object(mode, "_run_deterministic_session_ticks", side_effect=_run_ticks)

    mode.update(1.0 / 60.0)
    assert open_calls == 1
    assert mode._perk_pick_pending is True

    mode._perk_menu.timeline_ms = 0.0
    mode.update(1.0 / 60.0)
    assert open_calls == 1
    assert mode._perk_pick_pending is False

    mode.update(1.0 / 60.0)
    assert open_calls == 2


def test_open_perk_menu_ignores_reopen_while_menu_active(mocker, make_mode_config) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=_assets_dir()), config=cfg, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup", return_value=None)
    resources = SimpleNamespace(texture=lambda _texture_id: object())
    small_font = SimpleNamespace(cell_size=10, widths=[8] * 256)
    mocker.patch.object(render_resources_module, "runtime_resources_for", return_value=resources)
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=small_font)
    mode.open()

    mode._perk_menu.open = True

    record_checkpoint = mocker.patch.object(mode, "_record_replay_checkpoint")
    enqueue_command = mocker.patch.object(mode, "enqueue_input_command")

    mode._open_perk_menu()

    record_checkpoint.assert_not_called()
    enqueue_command.assert_not_called()
