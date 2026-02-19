from __future__ import annotations

import crimson.game.loop_view as loop_view
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers


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


def test_game_loop_draw_applies_gamma_shader_when_gain_non_default(monkeypatch, make_game_state) -> None:
    calls: list[object] = []
    state = make_game_state()
    state.gamma_ramp = 1.4
    view = GameLoopView(state)
    monkeypatch.setattr(view, "_draw_scene_layers", lambda: calls.append("scene"))

    sentinel_shader = object()

    monkeypatch.setattr(loop_view, "_get_gamma_ramp_shader", lambda: (sentinel_shader, 7))
    monkeypatch.setattr(
        loop_view,
        "_set_gamma_ramp_gain",
        lambda shader, gain_loc, gain: calls.append(("gain", shader, gain_loc, gain)),
    )
    monkeypatch.setattr(loop_view.rl, "begin_shader_mode", lambda shader: calls.append(("begin", shader)))
    monkeypatch.setattr(loop_view.rl, "end_shader_mode", lambda: calls.append("end"))

    view.draw()

    assert calls == [("gain", sentinel_shader, 7, 1.4), ("begin", sentinel_shader), "scene", "end"]


def test_game_loop_draw_skips_gamma_shader_for_default_gain(monkeypatch, make_game_state) -> None:
    calls: list[object] = []
    state = make_game_state()
    state.gamma_ramp = 1.0
    view = GameLoopView(state)
    monkeypatch.setattr(view, "_draw_scene_layers", lambda: calls.append("scene"))

    def _unexpected_shader_lookup() -> tuple[object, int]:
        raise AssertionError("gamma shader lookup should not happen for gain=1")

    monkeypatch.setattr(loop_view, "_get_gamma_ramp_shader", _unexpected_shader_lookup)

    view.draw()

    assert calls == ["scene"]
