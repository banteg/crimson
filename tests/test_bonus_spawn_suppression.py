from __future__ import annotations

from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState


def test_bonus_try_spawn_on_kill_suppressed_in_typo_mode() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.TYPO)

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None


def test_bonus_try_spawn_on_kill_suppressed_in_rush_mode() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.RUSH)

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None


def test_bonus_try_spawn_on_kill_suppressed_in_tutorial_mode() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.TUTORIAL)

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None


def test_bonus_try_spawn_on_kill_suppressed_in_demo_mode() -> None:
    state = GameplayState()
    state.demo_mode_active = True

    players = [PlayerState(index=0, pos=Vec2(256.0, 256.0))]
    assert state.bonus_pool.try_spawn_on_kill(pos=Vec2(300.0, 300.0), state=state, players=players) is None
