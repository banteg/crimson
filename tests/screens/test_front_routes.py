from __future__ import annotations

from crimson.game.loop_view import GameLoopView


def test_open_quests_from_play_game_route_restores_play_game_parent(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    route = loop._front_route("open_quests_from_play_game")
    quest_failed = loop._front_route("quest_failed")
    open_play_game = loop._front_route("open_play_game")
    open_quests = loop._front_route("open_quests")
    assert route is not None
    assert quest_failed is not None
    assert open_play_game is not None
    assert open_quests is not None

    current = quest_failed.view
    parent = open_play_game.view
    target = open_quests.view
    stacked = mocker.Mock()
    loop._front_stack = [stacked]

    current_close = mocker.patch.object(current, "close")
    parent_open = mocker.patch.object(parent, "open")
    target_open = mocker.patch.object(target, "open")

    handled = loop._transition_to_front_route(
        "open_quests_from_play_game",
        route,
        current=current,
        gameplay=None,
    )

    assert handled is True
    stacked.close.assert_called_once_with()
    current_close.assert_called_once_with()
    parent_open.assert_called_once_with()
    target_open.assert_called_once_with()
    assert loop._front_stack == [parent]
    assert loop._front_active is target
    assert loop._active is target
