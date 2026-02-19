from __future__ import annotations

from crimson.game.runtime import _boot_command_handlers


def test_telltimesurvived_uses_gameplay_elapsed_ms(make_game_state) -> None:
    state = make_game_state()
    state.survival_elapsed_ms = 12_999.0
    handlers = _boot_command_handlers(state)

    handlers["telltimesurvived"]([])

    assert state.console.log.lines[-1] == "Survived: 12 seconds."
