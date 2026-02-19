from __future__ import annotations

from crimson.game.runtime import _boot_command_handlers


def test_sndfreqadjustment_toggles_from_enabled_default(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.snd_freq_adjustment_enabled is True

    handlers["sndfreqadjustment"]([])
    assert state.snd_freq_adjustment_enabled is False
    assert state.console.log.lines[-1] == "Sound frequency adjustment is now disabled."

    handlers["sndfreqadjustment"]([])
    assert state.snd_freq_adjustment_enabled is True
    assert state.console.log.lines[-1] == "Sound frequency adjustment is now enabled."
