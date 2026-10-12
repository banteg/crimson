from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.modes.survival_mode import SurvivalMode
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.factories import player_input


@pytest.mark.usefixtures("headless_resources")
@pytest.mark.parametrize(
    ("preserve_bugs", "health", "contact_damage"),
    [
        (False, 3800.0, 40.0),
        # Original bug 38: the saved box toughens Survival's milestone waves.
        (True, 4560.0, 56.0),
    ],
)
def test_ticked_hardcore_box_reaches_survival_milestones_only_under_preserve_bugs(
    make_mode_config, assets_dir: Path, preserve_bugs: bool, health: float, contact_damage: float,
) -> None:
    config = make_mode_config(game_mode=GameMode.SURVIVAL, updates={"hardcore": True})
    mode = SurvivalMode(ViewContext(assets_dir=assets_dir, preserve_bugs=preserve_bugs), config=config, audio_rng=Crand(1))
    mode.open()
    try:
        session = mode._sim_session
        assert session is not None
        # The replay keeps the saved box and the bug policy, which decide the run between them.
        recorder = mode._replay_recorder
        assert recorder is not None
        assert (recorder.run.hardcore, recorder.run.preserve_bugs) == (True, preserve_bugs)

        # Level 9 sends the level 5 rings and the level 9 red boss in one tick.
        mode.player.level = 9
        session.step_tick(dt=1.0 / 60.0, inputs=[player_input()])

        [boss] = [creature for creature in mode.creatures.entries if creature.active and creature.max_hp == 3800.0]
        assert (boss.hp, boss.contact_damage) == (health, contact_damage)
    finally:
        mode.close()
