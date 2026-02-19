from __future__ import annotations

from crimson.frontend.panels.play_game import PlayGameMenuView
from crimson.game.loop_view import GameLoopView
from crimson.game.types import LanSessionConfig, PendingLanSession
from crimson.game_modes import GameMode


def test_play_game_network_entry_is_available_by_default(make_game_state) -> None:
    state = make_game_state()
    view = PlayGameMenuView(state)

    entries = view._mode_entries()[0]
    assert any(entry.action == "open_lan_session" for entry in entries)


def test_loop_view_maps_lan_start_action_into_mode_action(make_game_state) -> None:
    state = make_game_state()
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="quests",
            player_count=3,
            quest_level="1.1",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_quest_lan")

    assert action == "open_lan_lobby"
    assert state.config.game_mode == int(GameMode.QUESTS)
    assert state.config.player_count == 3
    assert state.pending_quest_level == "1.1"
    assert state.lan_in_lobby is True
    assert state.lan_waiting_for_players is True
    assert state.lan_expected_players == 3
    assert state.lan_connected_players == 1
    assert state.lan_runtime is not None


def test_non_lan_start_resets_lobby_wait_state(make_game_state) -> None:
    state = make_game_state()
    state.lan_in_lobby = True
    state.lan_waiting_for_players = True
    state.lan_expected_players = 4
    state.lan_connected_players = 2
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_survival")

    assert action == "start_survival"
    assert state.lan_in_lobby is False
    assert state.lan_waiting_for_players is False
    assert state.lan_expected_players == 1
    assert state.lan_connected_players == 1


def test_lan_match_start_action_does_not_close_runtime(make_game_state) -> None:
    state = make_game_state()
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="survival",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    loop = GameLoopView(state)

    assert loop._resolve_lan_action("start_survival_lan") == "open_lan_lobby"
    runtime = state.lan_runtime
    assert runtime is not None
    assert state.lan_in_lobby is True

    # The LAN lobby starts gameplay via the normal mode actions; keep LAN active.
    assert loop._resolve_lan_action("start_survival") == "start_survival"
    assert state.lan_in_lobby is True
    assert state.lan_runtime is runtime


def test_open_lan_session_route_allows_default_and_honors_explicit_cvar(make_game_state) -> None:
    state = make_game_state()
    loop = GameLoopView(state)

    assert loop._resolve_lan_action("open_lan_session") == "open_lan_session"
    state.console.register_cvar("cv_lanLockstepEnabled", "0")
    assert loop._resolve_lan_action("open_lan_session") == "open_play_game"


def test_auto_lan_start_action_consumes_pending_session_once(make_game_state) -> None:
    state = make_game_state()
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="rush",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    loop = GameLoopView(state)

    assert loop._auto_lan_start_action() == "start_rush_lan"
    assert state.pending_lan_session.started is True
    assert loop._auto_lan_start_action() is None


def test_cli_autostart_host_does_not_block_on_wait_gate(make_game_state) -> None:
    state = make_game_state()
    state.pending_lan_session = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="survival",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            host_ip="",
            port=31993,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_survival_lan")

    assert action == "open_lan_lobby"
    assert state.lan_in_lobby is True
    assert state.lan_waiting_for_players is True
    assert state.lan_expected_players == 2
    assert state.lan_connected_players == 1
    assert state.lan_runtime is not None
