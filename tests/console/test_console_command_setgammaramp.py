from __future__ import annotations

from unittest.mock import call

from crimson.game import loop_view
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.screens.stack import ScreenEntry
from tests.support.screens import ScreenStub


def test_setgammaramp_updates_state_and_logs(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"](["1.25"])

    assert state.gamma_ramp == 1.25
    assert state.console.log.lines[-1] == "Gamma ramp regenerated and multiplied with 1.250000"


def test_setgammaramp_prints_usage_on_bad_arity(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"]([])

    assert state.console.log.lines[-2:] == [
        "setGammaRamp <scalar > 0>",
        "Command adjusts gamma ramp linearly by multiplying with given scalar",
    ]


def test_game_loop_draw_applies_gamma_after_the_complete_dpi_sized_frame(mocker, make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.4
    view = GameLoopView(state)
    shader = loop_view.rl.Shader()
    shader.id = 1
    target = loop_view.rl.RenderTexture()
    target.id = 1
    target.texture.width, target.texture.height = 2048, 1536
    view._gamma_shader, view._gamma_gain_loc, view._gamma_target = shader, 7, target
    ensure = mocker.patch.object(view, "_ensure_gamma_resources")
    mocker.patch.object(loop_view.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(loop_view.rl, "get_screen_height", return_value=768)
    mocker.patch.object(loop_view.rl, "get_render_width", return_value=2048)
    mocker.patch.object(loop_view.rl, "get_render_height", return_value=1536)
    ordered = mocker.Mock()
    for name in ("begin_texture_mode", "end_texture_mode", "begin_shader_mode", "end_shader_mode",
                 "clear_background", "rl_push_matrix", "rl_pop_matrix", "rl_scalef", "draw_texture_pro"):
        ordered.attach_mock(mocker.patch.object(loop_view.rl, name), name)
    ordered.attach_mock(mocker.patch.object(view, "_draw_scene_layers"), "scene")
    ordered.attach_mock(mocker.patch.object(loop_view, "_set_gamma_ramp_gain"), "gain")

    view.draw()

    ensure.assert_called_once_with(2048, 1536)
    assert [entry[0] for entry in ordered.mock_calls] == [
        "begin_texture_mode", "clear_background", "rl_push_matrix", "rl_scalef", "scene", "rl_pop_matrix",
        "end_texture_mode", "gain", "begin_shader_mode", "draw_texture_pro", "end_shader_mode",
    ]
    ordered.rl_scalef.assert_called_once_with(2.0, 2.0, 1.0)
    ordered.gain.assert_called_once_with(shader, 7, 1.4)
    quad = ordered.draw_texture_pro.call_args.args
    assert quad[1].height == -1536
    assert quad[2].width == 1024 and quad[2].height == 768


def test_game_loop_draw_skips_gamma_shader_for_default_gain(mocker, make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.0
    view = GameLoopView(state)
    draw_scene = mocker.patch.object(view, "_draw_scene_layers")
    shader_lookup = mocker.patch.object(
        view,
        "_ensure_gamma_resources",
    )

    view.draw()

    shader_lookup.assert_not_called()
    draw_scene.assert_called_once_with()


def test_game_loop_draw_scene_layers_draws_fps_counter_after_console(mocker, make_game_state) -> None:
    state = make_game_state()
    view = GameLoopView(state)
    console = mocker.Mock()
    view.state.console = console

    state.screens.push(ScreenEntry(ScreenStub()))
    active_draw = mocker.patch.object(state.screens.active, "draw")
    ordered = mocker.Mock()
    ordered.attach_mock(active_draw, "active")
    ordered.attach_mock(console.draw, "console")
    ordered.attach_mock(console.draw_fps_counter, "fps")

    view._draw_scene_layers()

    assert ordered.mock_calls == [
        call.active(),
        call.console(),
        call.fps(),
    ]


def test_setgammaramp_rejects_invalid_values_without_changing_gain(make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.25
    handler = _boot_command_handlers(state)["setGammaRamp"]
    for value in ("0", "-1", "nan", "inf", "nonsense"):
        handler([value])
        assert state.gamma_ramp == 1.25
        assert "finite scalar" in state.console.log.lines[-1]


def test_trial_timer_commands_reject_nonfinite_values_and_bound_saved_u32(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)
    state.status.play_time_ms = 123
    state.demo_trial_elapsed_ms = 456
    for name in ("demoTrialSetPlaytime", "demoTrialSetGrace"):
        for value in ("nan", "inf", "nonsense"):
            handlers[name]([value])
    assert state.status.play_time_ms == 123
    assert state.demo_trial_elapsed_ms == 456
    handlers["demoTrialSetPlaytime"](["1e30"])
    assert state.status.play_time_ms == 0xFFFFFFFF


def test_gamma_releases_shader_when_uniform_is_missing(mocker, make_game_state) -> None:
    import pytest

    view = GameLoopView(make_game_state())
    shader = loop_view.rl.Shader()
    shader.id = 1
    mocker.patch.object(loop_view.rl, "load_shader_from_memory", return_value=shader)
    mocker.patch.object(loop_view.rl, "get_shader_location", return_value=-1)
    unload = mocker.patch.object(loop_view.rl, "unload_shader")
    with pytest.raises(RuntimeError, match="gain uniform"):
        view._ensure_gamma_resources(1024, 768)
    unload.assert_called_once_with(shader)
    assert view._gamma_shader is None


def test_gamma_resources_resize_and_close_without_leaks(mocker, make_game_state) -> None:
    view = GameLoopView(make_game_state())
    shader = loop_view.rl.Shader()
    shader.id = 1
    targets = [loop_view.rl.RenderTexture(), loop_view.rl.RenderTexture()]
    for target, size in zip(targets, [(1024, 768), (2048, 1536)], strict=True):
        target.id = 1
        target.texture.width, target.texture.height = size
    mocker.patch.object(loop_view.rl, "load_shader_from_memory", return_value=shader)
    mocker.patch.object(loop_view.rl, "get_shader_location", return_value=3)
    load = mocker.patch.object(loop_view.rl, "load_render_texture", side_effect=targets)
    mocker.patch.object(loop_view.rl, "rl_framebuffer_complete", return_value=True)
    unload_target = mocker.patch.object(loop_view.rl, "unload_render_texture")
    unload_shader = mocker.patch.object(loop_view.rl, "unload_shader")
    view._ensure_gamma_resources(1024, 768)
    view._ensure_gamma_resources(1024, 768)
    assert load.call_count == 1
    view._ensure_gamma_resources(2048, 1536)
    unload_target.assert_called_once_with(targets[0])
    view._close_gamma_resources()
    view._close_gamma_resources()
    assert unload_target.call_count == 2
    unload_shader.assert_called_once_with(shader)
