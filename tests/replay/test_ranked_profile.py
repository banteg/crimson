from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.replay.ranked import unranked_reasons
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec, RunStatus
from grim.geom import Vec2
from tests.support.factories import player_input

_FULL = RunStatus(quest_unlock_index=50, quest_unlock_index_full=50)


@pytest.mark.parametrize(
    ("run", "reasons"),
    [
        (RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL), []),
        (RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL, detail_preset=3), ["detail_preset"]),
        (RunSpec(game_mode_id=GameMode.RUSH, seed=1, status=_FULL, violence_disabled=1), ["violence_disabled"]),
        (RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL, friendly_fire=True), ["friendly_fire"]),
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


def test_friendly_fire_run_gives_player_shots_their_own_owner() -> None:
    spec = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, status=_FULL, player_count=2, friendly_fire=True)
    session = initialize_run(spec).session
    shooter = player_input(aim=Vec2(900.0, 512.0), fire_down=True, fire_pressed=True)
    owners: set[int] = set()
    # Runs start with the pistol's 0.8 s cooldown.
    for _ in range(60):
        session.step_tick(dt=1 / 60, inputs=(player_input(), shooter))
        owners |= {proj.owner_id for proj in session.world.state.projectiles.entries if proj.active}
    assert owners == {-2}
