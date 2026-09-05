from __future__ import annotations

from types import SimpleNamespace

from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.screens.stack import ScreenEntry
from tests.support.gameplay_screen import GameplayScreenStub


def test_generateterrain_command_sets_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


def test_game_loop_consumes_terrain_regenerate_request(make_game_state) -> None:
    class _DummyResources:
        def texture(self, *_args, **_kwargs):
            return SimpleNamespace(width=1, height=1)

    state = make_game_state()
    state.resources = _DummyResources()
    view = GameLoopView(state)
    fake = GameplayScreenStub()
    state.screens.push(ScreenEntry(fake, gameplay=fake))
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert state.menu_ground is not None
    assert fake.regenerate_calls == 1
