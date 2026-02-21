from __future__ import annotations

from pathlib import Path

import grim.console as console_module
from crimson.game.runtime import _apply_debug_console_defaults
from grim.console import ConsoleLog, ConsoleState


def _make_console() -> ConsoleState:
    return ConsoleState(base_dir=Path("."), log=ConsoleLog(base_dir=Path(".")))


def test_fps_counter_hidden_when_cvar_disabled(mocker) -> None:
    console = _make_console()
    console.register_cvar("cv_showFPS", "0")

    draw_small = mocker.patch.object(ConsoleState, "_draw_small_text")

    console.draw_fps_counter()

    draw_small.assert_not_called()


def test_fps_counter_draws_numeric_value_under_400(mocker) -> None:
    console = _make_console()
    console.register_cvar("cv_showFPS", "1")

    mocker.patch.object(console_module.rl, "get_fps", return_value=399)
    mocker.patch.object(console_module.rl, "get_screen_width", return_value=800)
    mocker.patch.object(console_module.rl, "get_screen_height", return_value=600)
    draw_small = mocker.patch.object(ConsoleState, "_draw_small_text")

    console.draw_fps_counter()

    assert draw_small.call_count == 1
    text, pos, color = draw_small.call_args.args
    assert text == "399"
    assert pos.x == 755.0
    assert pos.y == 576.0
    assert color.a == 153


def test_fps_counter_draws_400_plus_at_and_above_400(mocker) -> None:
    console = _make_console()
    console.register_cvar("cv_showFPS", "1")

    mocker.patch.object(console_module.rl, "get_fps", return_value=400)
    mocker.patch.object(console_module.rl, "get_screen_width", return_value=800)
    mocker.patch.object(console_module.rl, "get_screen_height", return_value=600)
    draw_small = mocker.patch.object(ConsoleState, "_draw_small_text")

    console.draw_fps_counter()

    assert draw_small.call_count == 1
    text, pos, color = draw_small.call_args.args
    assert text == "400+"
    assert pos.x == 749.0
    assert pos.y == 576.0
    assert color.a == 153


def test_debug_mode_enables_fps_cvar_by_default() -> None:
    console = _make_console()
    console.register_cvar("cv_showFPS", "0")

    _apply_debug_console_defaults(console, debug=True)

    cvar = console.cvars.get("cv_showFPS")
    assert cvar is not None
    assert cvar.value == "1"
    assert cvar.value_f == 1.0


def test_non_debug_mode_keeps_fps_cvar_default() -> None:
    console = _make_console()
    console.register_cvar("cv_showFPS", "0")

    _apply_debug_console_defaults(console, debug=False)

    cvar = console.cvars.get("cv_showFPS")
    assert cvar is not None
    assert cvar.value == "0"
    assert cvar.value_f == 0.0
