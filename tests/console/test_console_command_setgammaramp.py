from __future__ import annotations

from crimson.game import loop_view
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers


def test_setgammaramp_updates_state_and_logs(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"](["1.25"])

    assert state.gamma_ramp == 1.25
    assert state.console.log.lines[-1] == "Gamma ramp regenerated and multiplied with 1.250000"


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
                 "clear_background", "rl_scalef", "draw_texture_pro"):
        ordered.attach_mock(mocker.patch.object(loop_view.rl, name), name)
    ordered.attach_mock(mocker.patch.object(view, "_draw_scene_layers"), "scene")
    ordered.attach_mock(mocker.patch.object(loop_view, "_set_gamma_ramp_gain"), "gain")
    ordered.attach_mock(mocker.patch.object(loop_view, "opaque_blend"), "opaque")

    view.draw()

    ensure.assert_called_once_with(2048, 1536)
    assert [entry[0] for entry in ordered.mock_calls] == [
        "begin_texture_mode", "rl_scalef", "clear_background", "scene",
        "end_texture_mode", "gain", "begin_shader_mode",
        "opaque", "opaque().__enter__", "draw_texture_pro", "opaque().__exit__", "end_shader_mode",
    ]
    ordered.rl_scalef.assert_called_once_with(2.0, 2.0, 1.0)
    ordered.gain.assert_called_once_with(shader, 7, 1.4)
    quad = ordered.draw_texture_pro.call_args.args
    assert quad[1].height == -1536
    assert quad[2].width == 1024 and quad[2].height == 768


def test_setgammaramp_rejects_invalid_values_without_changing_gain(make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.25
    handler = _boot_command_handlers(state)["setGammaRamp"]
    for value in ("0", "-1", "nan", "inf", "nonsense"):
        handler([value])
        assert state.gamma_ramp == 1.25
        assert "finite scalar" in state.console.log.lines[-1]
