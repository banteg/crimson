from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from crimson.game.types import GameState
from crimson.rng_caller_static import RngCallerStatic
from crimson.screens.panels.alien_zookeeper import AlienZooKeeperView
from grim.rand import Crand, CrandLike, RecordingCrand
from tests.support.helpers import ScriptedCrand


def _view_with_rng(rng: CrandLike) -> AlienZooKeeperView:
    view = object.__new__(AlienZooKeeperView)
    view.state = SimpleNamespace(rng=rng)
    view._board = [0] * 36
    return view


def test_fill_empty_cells_uses_exact_native_caller() -> None:
    rng = RecordingCrand(Crand(123))
    view = _view_with_rng(rng)
    view._board = [0, -1, 2, -1, 4, 0] * 6

    view._fill_empty_cells()

    assert sum(1 for value in view._board if value == -1) == 0
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_FILL_EMPTY,
        RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_FILL_EMPTY,
    ] * 6


def test_reroll_board_no_initial_match_uses_exact_native_caller() -> None:
    latin_square = [(row + col) % 5 for row in range(6) for col in range(6)]
    rng = ScriptedCrand(latin_square)
    view = _view_with_rng(rng)
    view._reroll_board_no_initial_match()

    assert view._board == latin_square
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREDITS_SECRET_ALIEN_ZOOKEEPER_REROLL_FILL,
    ] * 36


def test_open_preserves_native_process_lifetime_puzzle_state() -> None:
    state = SimpleNamespace(
        config=SimpleNamespace(display=SimpleNamespace(width=1024)),
        pause_background=object(),
    )
    view = AlienZooKeeperView(cast(GameState, state))
    assert view._board == [0] * 36
    assert view._timer_ms == 0

    view._board[7] = 4
    view._selected_index = 7
    view._timer_ms = 1234
    view._anim_time_ms = 5678
    view._score = 9

    view.open()

    assert view._board[7] == 4
    assert view._selected_index == 7
    assert view._timer_ms == 1234
    assert view._anim_time_ms == 5678
    assert view._score == 9
