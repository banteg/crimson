from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.replay.ranked import unranked_reasons
from crimson.sim.run_spec import RunSpec, RunStatus

_FULL = RunStatus(quest_unlock_index=50, quest_unlock_index_full=50)


@pytest.mark.parametrize(
    ("run", "reasons"),
    [
        (RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL), []),
        (RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL, detail_preset=3), ["detail_preset"]),
        (RunSpec(game_mode_id=GameMode.RUSH, seed=1, status=_FULL, violence_disabled=1), ["violence_disabled"]),
        # Quest 5.10's Plasma Cannon is still locked at index 49.
        (
            RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=RunStatus(quest_unlock_index=49, quest_unlock_index_full=50)),
            ["unlocks"],
        ),
        # The Splitter Gun needs the hardcore index at 40.
        (
            RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=RunStatus(quest_unlock_index=50, quest_unlock_index_full=39)),
            ["unlocks"],
        ),
    ],
)
def test_unranked_reasons_name_each_setting_outside_the_ranked_profile(run: RunSpec, reasons: list[str]) -> None:
    assert unranked_reasons(run) == reasons
