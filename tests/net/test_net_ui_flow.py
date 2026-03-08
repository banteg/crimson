from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import crimson.screens.panels.network_lobby as lan_lobby_module
from crimson.game.loop_view import GameLoopView
from crimson.game.types import NetworkSessionConfig, PendingNetworkSession, RollbackEndpoint
from crimson.net.relay_protocol import RoomState
from crimson.quests.level import QuestLevel
from crimson.screens.panels.network_lobby import NetworkLobbyPanelView
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl


def _stub_runtime_resources(assets_dir: Path) -> RuntimeResources:
    tex = cast("rl.Texture", SimpleNamespace(width=1, height=1, id=1))
    return RuntimeResources(
        assets_dir=assets_dir,
        textures={texture_id: tex for texture_id in TextureId},
        small_font=cast(SmallFontData, SimpleNamespace(cell_size=8, widths=[8] * 256)),
    )


def test_network_session_panel_requires_room_code_for_join(make_game_state) -> None:
    from crimson.screens.panels.network_session import NetworkSessionPanelView

    state = make_game_state()
    panel = NetworkSessionPanelView(state)
    panel._role = "join"
    panel._host = "127.0.0.1"
    panel._room_code = ""

    panel._start_session()

    assert "Room code is required" in panel._error
    assert state.pending_network_session is None


def test_network_session_panel_writes_pending_network_session(make_game_state) -> None:
    from crimson.screens.panels.network_session import NetworkSessionPanelView

    state = make_game_state()
    panel = NetworkSessionPanelView(state)
    panel._role = "host"
    panel._mode_idx = 1  # rush
    panel._player_count = 3
    panel._host = "203.0.113.20"
    panel._port_text = "32031"
    panel._netcode_mode = "rollback"
    panel._room_code = "rb42"

    panel._start_session()

    pending = state.pending_network_session
    assert pending is not None
    assert pending.role == "host"
    assert pending.config.mode == "rush"
    assert pending.config.player_count == 3
    assert pending.config.netcode_mode == "rollback"
    endpoint = pending.config.endpoint
    assert endpoint.relay_host == "203.0.113.20"
    assert endpoint.relay_port == 32031
    assert endpoint.room_code == "rb42"


def test_loop_view_resolves_lan_action_using_pending_network_session(make_game_state) -> None:
    state = make_game_state()
    state.pending_network_session = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="rush",
            endpoint=RollbackEndpoint(
                relay_host="127.0.0.1",
                relay_port=31993,
                room_code=None,
            ),
            netcode_mode="rollback",
            player_count=2,
            quest_level=None,
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    loop = GameLoopView(state)

    action = loop._resolve_lan_action("start_rush_lan")

    assert action == "open_lan_lobby"
    assert state.network_runtime is not None
    assert state.network_in_lobby is True


def test_network_lobby_panel_shows_room_code_not_session_id(make_game_state, mocker) -> None:
    state = make_game_state()
    state.resources = _stub_runtime_resources(state.base_dir)
    pending = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="survival",
            endpoint=RollbackEndpoint(
                relay_host="127.0.0.1",
                relay_port=31993,
                room_code="zz99",
            ),
            netcode_mode="rollback",
            player_count=2,
            quest_level=None,
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
    )
    state.pending_network_session = pending
    state.network_runtime = cast(
        "Any",
        SimpleNamespace(
            lobby_state=lambda: RoomState(room_code="ab12", session_id="session123", player_count=2, slots=[]),
        ),
    )

    panel = NetworkLobbyPanelView(state)
    draw_small_text = mocker.patch.object(lan_lobby_module, "draw_small_text")
    mocker.patch.object(lan_lobby_module, "button_draw", return_value=None)
    mocker.patch.object(
        lan_lobby_module,
        "measure_small_text_width",
        side_effect=lambda _font, text: float(len(str(text)) * 8),
    )
    mocker.patch.object(
        panel,
        "_layout",
        side_effect=lambda: SimpleNamespace(
            scale=1.0,
            panel_top_left=Vec2(0.0, 0.0),
            base_pos=Vec2(0.0, 0.0),
            back_pos=Vec2(0.0, 0.0),
            back_w=64.0,
        ),
    )

    panel._draw_contents()

    captured = [str(call.args[1]) for call in draw_small_text.call_args_list]
    code_label_index = captured.index("Code:")
    assert captured[code_label_index + 1] == "ab12"
    assert "Session:" in captured


def test_network_lobby_panel_update_match_start_applies_state_and_transition(make_game_state) -> None:
    state = make_game_state()
    pending = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="quests",
            endpoint=RollbackEndpoint(
                relay_host="127.0.0.1",
                relay_port=31993,
                room_code="qz42",
            ),
            netcode_mode="rollback",
            player_count=2,
            quest_level=QuestLevel(1, 1),
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
    )
    state.pending_network_session = pending
    event = SimpleNamespace(mode_id=3, player_count=5, quest_level=QuestLevel(2, 4))
    state.network_runtime = cast(
        "Any",
        SimpleNamespace(
            error="",
            match_start=lambda: event,
        ),
    )

    panel = NetworkLobbyPanelView(state)
    panel._chrome.is_open = True
    panel._chrome.chrome.timeline_ms = 0
    panel._chrome.chrome.timeline_max_ms = 0

    panel.update(0.0)

    assert state.network_in_lobby is True
    assert state.network_waiting_for_players is False
    assert state.network_expected_players == 4
    assert state.network_connected_players == 4
    assert state.config.player_count == 4
    assert state.config.game_mode == 3
    assert state.pending_quest_level == QuestLevel(2, 4)
    assert panel._chrome.chrome.closing is True
    assert panel._chrome.chrome.close_action == "start_quest"
    assert state.screen_fade_ramp is True
