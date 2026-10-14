from __future__ import annotations

from crimson.game.runtime import _boot_command_handlers


def test_setgammaramp_updates_state_and_logs(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    handlers["setGammaRamp"](["1.25"])

    assert state.gamma_ramp == 1.25
    assert state.console.log.lines[-1] == "Gamma ramp regenerated and multiplied with 1.250000"


def test_setgammaramp_rejects_invalid_values_without_changing_gain(make_game_state) -> None:
    state = make_game_state()
    state.gamma_ramp = 1.25
    handler = _boot_command_handlers(state)["setGammaRamp"]
    for value in ("0", "-1", "nan", "inf", "nonsense"):
        handler([value])
        assert state.gamma_ramp == 1.25
        assert "finite scalar" in state.console.log.lines[-1]
