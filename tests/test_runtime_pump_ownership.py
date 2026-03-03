from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, LockstepSessionConfig, PendingNetworkSession


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
