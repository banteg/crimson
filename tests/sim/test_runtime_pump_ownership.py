"""Frame-driver orchestration tests.

These tests isolate orchestration logic (pump counting, stall detection,
sync emission suppression, telemetry propagation) from the sim layer
using mocks. The mocking is intentional: each test asserts an observable
behavioral contract of the frame-driver, not internal wiring.
"""

from __future__ import annotations

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.screens.stack import ScreenEntry
from tests.support.gameplay_screen import GameplayScreenStub


def test_gameplay_frame_telemetry_is_propagated_to_game_state(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    view = GameplayScreenStub(telemetry=(3, 2, 5, 1.25, 0.75, 0.5))
    state.screens.push(ScreenEntry(view, gameplay=view))

    mocker.patch.object(loop_view_module, "input_begin_frame", side_effect=lambda: None)
    mocker.patch.object(type(state.console), "handle_hotkey", return_value=None)
    mocker.patch.object(type(state.console), "update", return_value=None)
    mocker.patch.object(loop, "_sync_console_elapsed_ms", side_effect=lambda: None)
    mocker.patch.object(loop, "_handle_console_requests", side_effect=lambda: None)
    mocker.patch.object(loop, "_sync_rtx_mode", side_effect=lambda: None)
    mocker.patch.object(loop, "_tick_statistics_playtime", side_effect=lambda _dt: None)
    mocker.patch.object(loop_view_module, "debug_enabled", return_value=False)
    mocker.patch.object(loop_view_module, "_update_screen_fade", side_effect=lambda _state, _dt: None)

    loop.update(1.0 / 60.0)

    assert state.runtime_updates_per_frame == 3
    assert state.input_stall_count == 2
    assert state.ticks_advanced_per_frame == 5
    assert state.sim_ms == 1.25
    assert state.presentation_plan_ms == 0.75
    assert state.presentation_apply_ms == 0.5
