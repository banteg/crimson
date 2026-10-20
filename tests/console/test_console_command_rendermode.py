from __future__ import annotations

from crimson.game.runtime import _boot_command_handlers
from crimson.render.rtx.mode import RtxRenderMode


def test_rendermode_reports_and_sets_mode(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.rtx_mode is RtxRenderMode.CLASSIC

    handlers["rendermode"]([])
    assert state.console.log.lines[-1] == "Render mode is 'classic'."

    handlers["rendermode"](["rtx"])
    assert state.rtx_mode is RtxRenderMode.RTX
    assert state.console.log.lines[-1] == "Render mode set to 'rtx'."

    handlers["rendermode"](["classic"])
    assert state.rtx_mode is RtxRenderMode.CLASSIC
    assert state.console.log.lines[-1] == "Render mode set to 'classic'."


def test_togglertx_cycles_mode(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.rtx_mode is RtxRenderMode.CLASSIC

    handlers["togglertx"]([])
    assert state.rtx_mode is RtxRenderMode.RTX
    assert state.console.log.lines[-1] == "Render mode set to 'rtx'."

    handlers["togglertx"]([])
    assert state.rtx_mode is RtxRenderMode.CLASSIC
    assert state.console.log.lines[-1] == "Render mode set to 'classic'."


def test_rtxdebug_selects_display_only_view_and_reports_invalid_names(make_game_state, mocker):
    from crimson.render.rtx.debug import RtxDebugView
    from crimson.screens.stack import ScreenEntry

    state = make_game_state()
    screen = mocker.Mock()
    state.screens.push(ScreenEntry(screen))
    handler = _boot_command_handlers(state)["rtxdebug"]
    handler(["direct-unshadowed"])
    screen.set_rtx_debug.assert_called_once_with(RtxDebugView.DIRECT_UNSHADOWED)
    assert state.rtx_mode is RtxRenderMode.CLASSIC
    handler(["not-a-view"])
    assert state.console.log.lines[-1].startswith("rtxdebug <shaded|")
    assert screen.set_rtx_debug.call_count == 1


def test_rtxdebug_before_any_screen_opens_is_safe(make_game_state):
    state = make_game_state()
    _boot_command_handlers(state)["rtxdebug"](["direct"])
    assert state.console.log.lines[-1] == "rtxdebug requires an open game or replay."
