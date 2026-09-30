from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.gameplay import survival_level_threshold
from crimson.modes.survival_mode import SurvivalMode
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.factories import player_input


@pytest.mark.usefixtures("headless_resources")
def test_survival_mode_session_has_progression_enabled_and_levels_up(make_mode_config, assets_dir: Path) -> None:
    config = make_mode_config(game_mode=GameMode.SURVIVAL)
    mode = SurvivalMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(0xBEEF))
    mode.open()
    try:
        session = mode._sim_session
        assert session is not None
        assert bool(session.perk_progression_enabled) is True

        mode.player.level = 1
        mode.player.experience = survival_level_threshold(1) + 1
        mode.state.perk_selection.pending_count = 0

        session.step_tick(dt=1.0 / 60.0, inputs=[player_input()])

        assert int(mode.player.level) == 2
        assert int(mode.state.perk_selection.pending_count) == 1
    finally:
        mode.close()
