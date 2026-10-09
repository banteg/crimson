from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


@pytest.mark.parametrize("game_mode", [GameMode.TYPO, GameMode.TUTORIAL])
def test_bonus_try_spawn_on_kill_suppressed_modes(game_mode: GameMode) -> None:
    state = GameplayState()
    state.game_mode = game_mode

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None
