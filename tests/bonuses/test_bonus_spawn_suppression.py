from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


@pytest.mark.parametrize(
    ("game_mode", "demo_mode_active"),
    [
        (GameMode.TYPO, False),
        (GameMode.RUSH, False),
        (GameMode.TUTORIAL, False),
        (None, True),
    ],
    ids=["typo", "rush", "tutorial", "demo"],
)
def test_bonus_try_spawn_on_kill_suppressed_modes(
    game_mode: GameMode | None,
    demo_mode_active: bool,
) -> None:
    state = GameplayState()
    if game_mode is not None:
        state.game_mode = game_mode
    state.demo_mode_active = demo_mode_active

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None
