from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.screens.actions import Route
from grim.assets import RuntimeResources


@pytest.fixture
def loop(make_game_state, headless_resources: RuntimeResources, headless_window) -> GameLoopView:
    """The game loop on the main menu with the real runtime resources and no window; input reports nothing."""
    view = GameLoopView(make_game_state(resources=headless_resources))
    view.navigation.open()
    view.navigation.navigate(Route.MENU)
    return view
