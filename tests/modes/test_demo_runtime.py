from __future__ import annotations

from crimson.demo import DemoView


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
