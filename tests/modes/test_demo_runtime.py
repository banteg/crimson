from __future__ import annotations

from crimson.demo import DemoView
from crimson.rng_caller_static import RngCallerStatic
from tests.support.helpers import ScriptedCrand


def test_demo_view_update_advances_simulation_time(make_game_state) -> None:
    state = make_game_state(demo_enabled=True)
    view = DemoView(state)
    view._demo_variant_index = 0
    view._demo_mode_start()

    runtime = view._runtime
    assert runtime.sim_world.presentation_elapsed_ms == 0.0

    view.update(1.0 / 60.0)

    assert runtime.sim_world.presentation_elapsed_ms > 0.0


def test_demo_view_draw_is_noop_after_close(make_game_state) -> None:
    state = make_game_state(demo_enabled=True)
    view = DemoView(state)

    view.close()
    view.draw()


def test_demo_variant_rng_setup_uses_exact_native_callers(make_game_state, mocker) -> None:
    state = make_game_state(demo_enabled=True)
    view = DemoView(state)
    rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    view._runtime.sim_world.state.rng = rng

    mocker.patch.object(view, "_setup_world_players")
    mocker.patch.object(view, "_apply_terrain_setup")
    mocker.patch.object(view, "_spawn")

    variant_1_callers: list[RngCallerStatic] = []
    for idx in range(20):
        variant_1_callers.extend(
            [
                RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_X,
                RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_Y,
            ],
        )
        if idx % 3 != 0:
            variant_1_callers.extend(
                [
                    RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_X,
                    RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_Y,
                ],
            )

    view._setup_variant_1()
    assert [record.caller for record in rng.records_since()] == variant_1_callers

    rng.srand(0)

    variant_3_callers: list[RngCallerStatic] = []
    for idx in range(20):
        variant_3_callers.extend(
            [
                RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_X,
                RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_Y,
            ],
        )
        if idx % 3 != 0:
            variant_3_callers.extend(
                [
                    RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_X,
                    RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_Y,
                ],
            )

    view._setup_variant_3()
    assert [record.caller for record in rng.records_since()] == variant_3_callers
