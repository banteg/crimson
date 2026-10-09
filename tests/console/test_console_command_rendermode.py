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
