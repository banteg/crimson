from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from crimson.game.loop_view import GameLoopView
from crimson.game.types import BackToPrevious, FrontRouteId
from grim.assets import RuntimeResources
from grim.raylib_api import rl
from tests.support.gameplay_screen import GameplayScreenStub


def _resources_stub() -> RuntimeResources:
    texture = rl.Texture()
    return cast(
        "RuntimeResources",
        SimpleNamespace(
            texture=lambda _texture_id: texture,
            small_font=SimpleNamespace(cell_size=8, widths=[8] * 256),
        ),
    )


def _open_quests_from_play_game(loop: GameLoopView) -> tuple[object, object]:
    current_route = loop._front_route(FrontRouteId.QUEST_FAILED)
    route = loop._front_route(FrontRouteId.OPEN_QUESTS)
    parent_route = loop._front_route(FrontRouteId.OPEN_PLAY_GAME)
    current = current_route.view
    current.open()
    loop._front_active = current
    loop._active = current
    loop._front_stack = [GameplayScreenStub()]

    loop._transition_to_front_route_with_parent(
        FrontRouteId.OPEN_QUESTS,
        parent=FrontRouteId.OPEN_PLAY_GAME,
        clear_stack=True,
        current=current,
        gameplay=None,
    )

    assert loop._front_active is route.view
    assert loop._front_stack == [parent_route.view]
    return current, loop._front_stack[0]


def test_open_quests_from_play_game_rebuilds_parent_stack(make_game_state) -> None:
    state = make_game_state()
    state.resources = _resources_stub()
    loop = GameLoopView(state)

    current, parent = _open_quests_from_play_game(loop)

    assert current is not parent
    assert loop.state.pause_background is None


def test_quest_list_back_returns_to_play_game_after_play_another(make_game_state, mocker) -> None:
    state = make_game_state()
    state.resources = _resources_stub()
    loop = GameLoopView(state)
    _current, parent = _open_quests_from_play_game(loop)
    quest_list = loop._front_active
    assert quest_list is not None

    quest_update = mocker.patch.object(quest_list, "update", return_value=None)
    mocker.patch.object(quest_list, "take_action", return_value=BackToPrevious())
    resume_from_child = mocker.patch.object(parent, "resume_from_child")

    loop.update(0.0)

    quest_update.assert_called_once_with(0.0)
    resume_from_child.assert_called_once_with()
    assert loop._front_active is parent
    assert loop._active is parent
    assert loop._front_stack == []
