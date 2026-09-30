from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.game_modes import GameMode
from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.screens.actions import Route, StartRun
from crimson.screens.chrome import ensure_menu_ground
from crimson.screens.pause_menu import PauseMenuView
from crimson.sim.terrain_generate import terrain_generate_random
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.rand import Crand

pytestmark = pytest.mark.usefixtures("headless_window")


@pytest.fixture
def state(make_game_state, headless_resources: RuntimeResources) -> GameState:
    return make_game_state(resources=headless_resources)


def _run_from_menu(state: GameState) -> tuple[GameLoopView, BaseGameplayMode]:
    """Open the main menu, start a survival run from it and play it for half a second."""
    loop = GameLoopView(state)
    loop.navigation.open()
    loop.navigation.navigate(Route.MENU)
    assert state.menu_ground is not None
    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))
    run = state.screens.gameplay
    assert isinstance(run, BaseGameplayMode)
    for _ in range(30):
        loop.update(0.016)
    return loop, run


def test_leaving_a_run_hands_its_ground_and_camera_to_the_menu(state: GameState) -> None:
    loop, run = _run_from_menu(state)
    menu_ground = state.menu_ground
    run_ground = run.render_resources.ground
    run_camera = run.camera
    assert run_ground is not None and run_ground is not menu_ground

    loop.navigation.navigate(Route.MENU)

    assert state.menu_ground is run_ground
    assert state.menu_ground_camera == run_camera
    assert run.steal_ground_for_menu() is None


def test_quitting_from_the_pause_menu_hands_the_run_ground_to_the_menu(state: GameState) -> None:
    loop, run = _run_from_menu(state)
    loop.navigation.navigate(Route.PAUSE)
    assert isinstance(state.screens.active, PauseMenuView)
    run_ground = run.render_resources.ground
    run_camera = run.camera
    assert run_ground is not None

    loop.navigation.navigate(Route.MENU)

    assert state.menu_ground is run_ground
    assert state.menu_ground_camera == run_camera
    assert run.steal_ground_for_menu() is None


def test_regenerate_menu_ground_resets_menu_camera(state: GameState) -> None:
    state.menu_ground_camera = Vec2(-100.0, -200.0)

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground is not None
    assert state.menu_ground_camera is None


def test_regenerate_menu_ground_unlock_branch_selects_q4_variant(
    state: GameState, headless_resources: RuntimeResources,
) -> None:
    state.status.quest_unlock_index = 0x28
    # terrain_generate_random() burns three hidden prelude draws before the
    # unlock-gated variant rolls; seed 2's fourth draw passes the Q4 gate (& 7 == 3).
    state.rng.srand(2)

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground.texture is headless_resources.texture(TextureId.TER_Q4_BASE)
    assert ground.overlay is headless_resources.texture(TextureId.TER_Q4_OVERLAY)
    assert ground.overlay_detail is headless_resources.texture(TextureId.TER_Q4_BASE)


def test_regenerate_menu_ground_draws_random_terrain_from_app_rng(state: GameState) -> None:
    state.status.quest_unlock_index = 0x28
    state.rng.srand(0x1234)
    expected_rng = Crand(int(state.rng.state))
    expected_terrain = terrain_generate_random(expected_rng, int(state.status.quest_unlock_index))

    ground = ensure_menu_ground(state, regenerate=True)

    assert ground._scheduled_layers == expected_terrain.layers
    assert int(state.rng.state) == int(expected_rng.state)


def test_existing_menu_ground_ignores_runtime_texture_scale_changes(state: GameState) -> None:
    ground = ensure_menu_ground(state, regenerate=True)
    state.menu_ground_camera = Vec2(-100.0, -200.0)
    before_rng_state = int(state.rng.state)
    before_layers = ground._scheduled_layers

    state.config.display.texture_scale = 0.5

    same_ground = ensure_menu_ground(state)

    assert same_ground is ground
    assert float(same_ground.texture_scale) == 1.0
    assert same_ground._scheduled_layers is before_layers
    assert int(state.rng.state) == before_rng_state
    assert state.menu_ground_camera == Vec2(-100.0, -200.0)
