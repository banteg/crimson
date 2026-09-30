from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers
from crimson.game_modes import GameMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.screens.actions import StartRun
from grim.rand import Crand
from grim.view import ViewContext


def test_generateterrain_command_sets_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


@pytest.mark.usefixtures("headless_window")
def test_game_loop_consumes_terrain_regenerate_request(make_game_state, headless_resources) -> None:
    state = make_game_state(resources=headless_resources)
    view = GameLoopView(state)
    view.navigation.navigate(StartRun(GameMode.SURVIVAL))
    run = state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    started = run.world_runtime.terrain_setup
    assert started is not None
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert state.menu_ground is not None
    regenerated = run.world_runtime.terrain_setup
    assert regenerated is not None
    assert regenerated.layers.base != started.layers.base


@pytest.mark.usefixtures("headless_resources")
def test_gameplay_terrain_regeneration_keeps_gameplay_rng_and_slots(make_mode_config, assets_dir) -> None:
    mode = SurvivalMode(
        ViewContext(assets_dir=assets_dir),
        config=make_mode_config(game_mode=GameMode.SURVIVAL),
        audio_rng=Crand(0xBEEF),
    )
    mode.open()
    started = mode.world_runtime.terrain_setup
    assert started is not None
    rng_state = mode.state.rng.state

    mode.regenerate_terrain_for_console()
    first = mode.world_runtime.terrain_setup
    mode.regenerate_terrain_for_console()
    second = mode.world_runtime.terrain_setup

    assert first is not None
    assert second is not None
    assert mode.state.rng.state == rng_state
    assert first.terrain_slots == second.terrain_slots == started.terrain_slots
    # Each command draws new stamps: the counter keeps repeats from reusing the same detached seed.
    assert len({started.layers.base, first.layers.base, second.layers.base}) == 3
    ground = mode.render_resources.ground
    assert ground is not None
    assert ground._scheduled_layers is second.layers
