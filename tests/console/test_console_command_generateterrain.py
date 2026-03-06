from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from tests.support.gameplay_screen import GameplayScreenStub


def test_generateterrain_command_sets_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


def test_game_loop_consumes_terrain_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    view = GameLoopView(state)
    fake = GameplayScreenStub()
    view._front_active = fake
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert state.menu_ground is None
    assert fake.regenerate_calls == 1
