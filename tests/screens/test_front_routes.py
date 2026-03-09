from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.types import FrontRouteId


def test_open_front_route_with_parent_restores_play_game_parent(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    quest_failed = loop._front_route(FrontRouteId.QUEST_FAILED)
    open_play_game = loop._front_route(FrontRouteId.OPEN_PLAY_GAME)
    open_quests = loop._front_route(FrontRouteId.OPEN_QUESTS)

    current = quest_failed.view
    parent = open_play_game.view
    target = open_quests.view
    stacked = mocker.Mock()
    loop._front_stack = [stacked]

    current_close = mocker.patch.object(current, "close")
    parent_open = mocker.patch.object(parent, "open")
    target_open = mocker.patch.object(target, "open")

    loop._transition_to_front_route_with_parent(
        FrontRouteId.OPEN_QUESTS,
        parent=FrontRouteId.OPEN_PLAY_GAME,
        clear_stack=True,
        current=current,
        gameplay=None,
    )

    stacked.close.assert_called_once_with()
    current_close.assert_called_once_with()
    parent_open.assert_called_once_with()
    target_open.assert_called_once_with()
    assert loop._front_stack == [parent]
    assert loop._front_active is target
    assert loop._active is target
