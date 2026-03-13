from __future__ import annotations

from typing import Literal

from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, NetworkSessionConfig, PendingNetworkSession
from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.screens.panels.play_game import PlayGameMenuView


def test_play_game_network_entry_is_available_by_default(make_game_state) -> None:
    state = make_game_state()
    view = PlayGameMenuView(state)

    entries = view._mode_entries()[0]
    assert any(entry.action == "open_lan_session" for entry in entries)


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


def test_loop_view_maps_lan_start_action_into_mode_action(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="quests", players=3, quest_level=QuestLevel(1, 1))
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_quest_lan")

    assert action == "open_lan_lobby"
    assert state.config.gameplay.mode == int(GameMode.QUESTS)
    assert state.config.gameplay.player_count == 3
    assert state.pending_quest_level == QuestLevel(1, 1)
    assert state.network_in_lobby is True
    assert state.network_waiting_for_players is True
    assert state.network_expected_players == 3
    assert state.network_connected_players == 1
    assert state.network_runtime is not None


def test_non_lan_start_resets_lobby_wait_state(make_game_state) -> None:
    state = make_game_state()
    state.network_in_lobby = True
    state.network_waiting_for_players = True
    state.network_expected_players = 4
    state.network_connected_players = 2
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_survival")

    assert action == "start_survival"
    assert state.network_in_lobby is False
    assert state.network_waiting_for_players is False
    assert state.network_expected_players == 1
    assert state.network_connected_players == 1


def test_lan_match_start_action_does_not_close_runtime(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="survival", players=2, auto_start=True)
    loop = GameLoopView(state)

    assert loop._resolve_lan_action("start_survival_lan") == "open_lan_lobby"
    runtime = state.network_runtime
    assert runtime is not None
    assert state.network_in_lobby is True

    # The LAN lobby starts gameplay via the normal mode actions; keep runtime alive.
    assert loop._resolve_lan_action("start_survival") == "start_survival"
    assert state.network_in_lobby is True
    assert state.network_runtime is runtime


def test_open_lan_session_route_allows_default_and_honors_explicit_cvar(make_game_state) -> None:
    state = make_game_state()
    loop = GameLoopView(state)

    assert loop._resolve_lan_action("open_lan_session") == "open_lan_session"
    state.console.register_cvar("cv_lanLockstepEnabled", "0")
    assert loop._resolve_lan_action("open_lan_session") == "open_play_game"


def test_auto_lan_start_action_consumes_pending_session_once(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="rush", players=2, auto_start=True)
    loop = GameLoopView(state)

    assert loop._auto_lan_start_action() == "start_rush_lan"
    assert state.pending_network_session.started is True
    assert loop._auto_lan_start_action() is None


def test_cli_autostart_host_does_not_block_on_wait_gate(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = _lockstep_pending(mode="survival", players=2, auto_start=True)
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_survival_lan")

    assert action == "open_lan_lobby"
    assert state.network_in_lobby is True
    assert state.network_waiting_for_players is True
    assert state.network_expected_players == 2
    assert state.network_connected_players == 1
    assert state.network_runtime is not None
