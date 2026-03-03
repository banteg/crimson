from __future__ import annotations

import inspect

import crimson.game.loop_view as loop_view_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, LockstepSessionConfig, PendingNetworkSession
from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode


class _DummyRuntime:
    def __init__(self) -> None:
        self.open_calls = 0
        self.update_calls = 0
        self.desync_count = 0
        self.error = ""

    def open(self) -> None:
        self.open_calls += 1

    def update(self) -> None:
        self.update_calls += 1

    def lobby_state(self):
        return None


def _pending_session() -> PendingNetworkSession:
    return PendingNetworkSession(
        role="host",
        config=LockstepSessionConfig(
            mode="survival",
            endpoint=LockstepEndpoint(),
            player_count=2,
        ),
    )


def test_interactive_frame_driver_pumps_runtime_once(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _pending_session()
    state.network_in_lobby = True
    runtime = _DummyRuntime()
    state.network_runtime = runtime
    loop = GameLoopView(state)

    loop._tick_network_runtime()

    assert runtime.open_calls == 1
    assert runtime.update_calls == 1
    assert state.runtime_updates_per_frame == 1


def test_interactive_headless_no_runtime_pumps_zero(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _pending_session()
    state.network_in_lobby = True
    state.network_runtime = None
    loop = GameLoopView(state)

    loop._tick_network_runtime()

    assert state.runtime_updates_per_frame == 0


def test_replay_frame_driver_pumps_runtime_once_when_present(replay_playback_view) -> None:
    view, _console = replay_playback_view
    runtime = _DummyRuntime()
    setattr(view, "_runtime", runtime)

    view._tick_network_runtime()

    assert runtime.open_calls == 1
    assert runtime.update_calls == 1
    assert getattr(view, "_runtime_updates_per_frame") == 1


def test_replay_headless_context_without_runtime_pumps_zero(replay_playback_view) -> None:
    view, _console = replay_playback_view
    setattr(view, "_runtime", None)

    view._tick_network_runtime()

    assert getattr(view, "_runtime_updates_per_frame") == 0


def test_gameplay_mode_lan_update_paths_do_not_pump_runtime_directly() -> None:
    lan_methods = (
        SurvivalMode._update_lan_match,
        RushMode._update_lan_match,
        QuestMode._update_lan_match,
    )
    for method in lan_methods:
        source = inspect.getsource(method)
        assert "runtime.update(" not in source


def test_lan_tick_consumption_uses_tick_runner_instead_of_direct_step_call() -> None:
    source = inspect.getsource(BaseGameplayMode._consume_lan_tick_frames)
    assert "advance_frame(" in source
    assert "session.step_tick(" not in source


def test_lan_tick_consumption_delegates_finalize_side_effects_to_helper() -> None:
    source = inspect.getsource(BaseGameplayMode._consume_lan_tick_frames)
    assert "_finalize_lan_tick(" in source
    assert "runtime.note_desync(" not in source
    assert "broadcast_tick_frame(" not in source


def test_gameplay_modes_no_longer_use_mode_local_sim_clock() -> None:
    lan_methods = (
        SurvivalMode.update,
        RushMode.update,
        QuestMode.update,
    )
    for method in lan_methods:
        source = inspect.getsource(method)
        assert "_sim_clock" not in source


def test_gameplay_modes_no_longer_define_mode_local_lan_capture_clock() -> None:
    for mode_type in (SurvivalMode, RushMode, QuestMode):
        source = inspect.getsource(mode_type.__init__)
        assert "_lan_capture_clock" not in source


def test_gameplay_frame_telemetry_is_propagated_to_game_state(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)

    class _FakeGameplayView:
        def open(self) -> None:
            return

        def close(self) -> None:
            return

        def update(self, dt: float) -> None:
            _ = dt

        def draw(self) -> None:
            return

        def take_action(self) -> str | None:
            return None

        def set_runtime_updates_per_frame(self, value: int) -> None:
            _ = value

        def frame_telemetry(self) -> tuple[int, int, int, float, float, float]:
            return (3, 2, 5, 1.25, 0.75, 0.5)

    view = _FakeGameplayView()
    loop._front_active = view
    loop._active = view
    loop._gameplay_views = frozenset({view})

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
