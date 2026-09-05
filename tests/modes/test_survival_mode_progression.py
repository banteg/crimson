from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import survival_level_threshold
from crimson.modes import base_gameplay_mode
from crimson.modes.survival_mode import SurvivalMode
from crimson.sim.input import PlayerInput
from grim.rand import Crand
from grim.view import ViewContext


def _assets_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "assets"


def test_survival_mode_session_has_progression_enabled_and_levels_up(mocker, make_mode_config) -> None:
    config = make_mode_config(game_mode=GameMode.SURVIVAL)
    mode = SurvivalMode(ViewContext(assets_dir=_assets_dir()), config=config, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mode.open()
    try:
        session = mode._sim_session
        assert session is not None
        assert bool(session.perk_progression_enabled) is True

        mode.player.level = 1
        mode.player.experience = survival_level_threshold(1) + 1
        mode.state.perk_selection.pending_count = 0

        session.step_tick(dt=1.0 / 60.0, inputs=[PlayerInput()])

        assert int(mode.player.level) == 2
        assert int(mode.state.perk_selection.pending_count) == 1
    finally:
        mode.close()
