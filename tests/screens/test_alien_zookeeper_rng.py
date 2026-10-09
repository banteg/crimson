from __future__ import annotations

from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.panels.alien_zookeeper import AlienZooKeeperView, _credits_secret_match3_find
from grim.rand import Crand


def _traced_view(make_game_state, seed: int) -> tuple[AlienZooKeeperView, list[int | None]]:
    rng = Crand(seed)
    callers: list[int | None] = []
    rng.set_trace_sink(lambda _before, _after, _value, caller: callers.append(caller))
    return AlienZooKeeperView(make_game_state(rng=rng)), callers


def test_fill_empty_cells_uses_exact_native_caller(make_game_state) -> None:
    view, callers = _traced_view(make_game_state, 123)
    view._board = [0, -1, 2, -1, 4, 0] * 6

    view._fill_empty_cells()

    assert -1 not in view._board
    assert callers == [RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_FILL_EMPTY] * 12


def test_reroll_board_no_initial_match_uses_exact_native_caller(make_game_state) -> None:
    view, callers = _traced_view(make_game_state, 123)

    view._reroll_board_no_initial_match()

    has_match, _idx, _direction = _credits_secret_match3_find(view._board)
    assert not has_match
    assert callers
    assert len(callers) % 36 == 0
    assert set(callers) == {RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_REROLL_FILL}
