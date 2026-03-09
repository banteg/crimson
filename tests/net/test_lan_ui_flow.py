from __future__ import annotations

from typing import Literal

from crimson.game.loop_view import GameLoopView
from crimson.game.types import (
    FrontRouteId,
    LockstepEndpoint,
    NetworkSessionConfig,
    OpenFrontRoute,
    OpenLanLobby,
    PendingNetworkSession,
    StartLanMatch,
)
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.screens.panels.play_game import PlayGameMenuView


def test_play_game_network_entry_is_available_by_default(make_game_state) -> None:
    state = make_game_state()
    view = PlayGameMenuView(state)

    entries = view._mode_entries()[0]
    assert any(entry.action == OpenFrontRoute(FrontRouteId.OPEN_LAN_SESSION) for entry in entries)


def _lockstep_pending(
    *,
    mode: Literal["survival", "rush", "quests"],
    players: int,
    quest_level: QuestLevel | None = None,
    auto_start: bool = False,
) -> PendingNetworkSession:
    return PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode=mode,
            endpoint=LockstepEndpoint(
                bind_host="0.0.0.0",
                host="127.0.0.1",
                port=31993,
            ),
            netcode_mode="lockstep",
            player_count=players,
            quest_level=quest_level,
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=auto_start,
    )


def test_loop_view_prepares_lan_lobby_for_pending_session(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="quests", players=3, quest_level=QuestLevel(1, 1))
    loop = GameLoopView(state)

    loop._prepare_lan_lobby(FrontRouteId.START_QUEST)

    assert state.config.game_mode == int(GameMode.QUESTS)
    assert state.config.player_count == 3
    assert state.pending_quest_level == QuestLevel(1, 1)
    assert state.network_in_lobby is True
    assert state.network_waiting_for_players is True
    assert state.network_expected_players == 3
    assert state.network_connected_players == 1
    assert state.network_runtime is not None


def test_reset_local_network_state_clears_lobby_wait_state(make_game_state) -> None:
    state = make_game_state()
    state.network_in_lobby = True
    state.network_waiting_for_players = True
    state.network_expected_players = 4
    state.network_connected_players = 2
    loop = GameLoopView(state)

    loop._reset_local_network_state()

    assert state.network_in_lobby is False
    assert state.network_waiting_for_players is False
    assert state.network_expected_players == 1
    assert state.network_connected_players == 1


def test_prepare_lan_match_does_not_close_runtime(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="survival", players=2, auto_start=True)
    loop = GameLoopView(state)

    loop._prepare_lan_lobby(FrontRouteId.START_SURVIVAL)
    runtime = state.network_runtime
    assert runtime is not None
    assert state.network_in_lobby is True

    loop._prepare_lan_match(StartLanMatch(route=FrontRouteId.START_SURVIVAL, player_count=2))

    assert state.network_in_lobby is True
    assert state.network_runtime is runtime


def test_open_lan_session_route_allows_default_and_honors_explicit_cvar(make_game_state, mocker) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    transition = mocker.patch.object(loop, "_transition_to_front_route")

    loop._apply_screen_action(OpenFrontRoute(FrontRouteId.OPEN_LAN_SESSION), current=None, gameplay=None)
    transition.assert_called_once_with(FrontRouteId.OPEN_LAN_SESSION, current=None, gameplay=None)

    state = make_game_state()
    state.console.register_cvar("cv_lanLockstepEnabled", "0")
    loop = GameLoopView(state)
    transition = mocker.patch.object(loop, "_transition_to_front_route")
    loop._apply_screen_action(OpenFrontRoute(FrontRouteId.OPEN_LAN_SESSION), current=None, gameplay=None)
    transition.assert_called_once_with(FrontRouteId.OPEN_PLAY_GAME, current=None, gameplay=None)
    assert state.network_last_error == "LAN UI is disabled (set cv_lanLockstepEnabled 1 to enable)."


def test_auto_lan_start_action_consumes_pending_session_once(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="rush", players=2, auto_start=True)
    loop = GameLoopView(state)

    assert loop._auto_lan_start_action() == OpenLanLobby(FrontRouteId.START_RUSH)
    assert state.pending_network_session.started is True
    assert loop._auto_lan_start_action() is None


def test_cli_autostart_host_does_not_block_on_wait_gate(make_game_state, mocker) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="survival", players=2, auto_start=True)
    loop = GameLoopView(state)
    transition = mocker.patch.object(loop, "_transition_to_front_route")

    action = loop._auto_lan_start_action()

    assert action == OpenLanLobby(FrontRouteId.START_SURVIVAL)
    assert action is not None
    loop._apply_screen_action(action, current=None, gameplay=None)
    transition.assert_called_once_with(FrontRouteId.OPEN_LAN_LOBBY, current=None, gameplay=None)
    assert state.network_in_lobby is True
    assert state.network_waiting_for_players is True
    assert state.network_expected_players == 2
    assert state.network_connected_players == 1
    assert state.network_runtime is not None
