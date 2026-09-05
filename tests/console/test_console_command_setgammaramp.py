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


def test_game_loop_draw_applies_gamma_shader_when_gain_non_default(mocker, make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.4
    view = GameLoopView(state)
    draw_scene = mocker.patch.object(view, "_draw_scene_layers")

    sentinel_shader = object()

    mocker.patch.object(loop_view, "_get_gamma_ramp_shader", return_value=(sentinel_shader, 7))
    set_gain = mocker.patch.object(
        loop_view,
        "_set_gamma_ramp_gain",
    )
    begin_shader = mocker.patch.object(loop_view.rl, "begin_shader_mode")
    end_shader = mocker.patch.object(loop_view.rl, "end_shader_mode")
    ordered = mocker.Mock()
    ordered.attach_mock(set_gain, "gain")
    ordered.attach_mock(begin_shader, "begin")
    ordered.attach_mock(draw_scene, "scene")
    ordered.attach_mock(end_shader, "end")

    view.draw()

    assert ordered.mock_calls == [
        call.gain(sentinel_shader, 7, 1.4),
        call.begin(sentinel_shader),
        call.scene(),
        call.end(),
    ]


def test_game_loop_draw_skips_gamma_shader_for_default_gain(mocker, make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.0
    view = GameLoopView(state)
    draw_scene = mocker.patch.object(view, "_draw_scene_layers")
    shader_lookup = mocker.patch.object(
        loop_view,
        "_get_gamma_ramp_shader",
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
