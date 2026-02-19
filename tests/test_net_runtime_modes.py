from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game.types import LanSessionConfig, LanSessionMode, PendingLanSession
from crimson.game_modes import GameMode
from crimson.net.net_runtime import NetRuntime


@pytest.mark.parametrize(
    ("mode", "action", "mode_id", "quest_level"),
    [
        ("survival", "start_survival_lan", int(GameMode.SURVIVAL), ""),
        ("rush", "start_rush_lan", int(GameMode.RUSH), ""),
        ("quests", "start_quest_lan", int(GameMode.QUESTS), "1.1"),
    ],
)
def test_rollback_runtime_is_selected_for_all_network_modes(
    make_game_state,
    mode: LanSessionMode,
    action: str,
    mode_id: int,
    quest_level: str,
) -> None:
    state = make_game_state()
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode=mode,
            player_count=2,
            quest_level=quest_level,
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_net_session = pending
    state.pending_lan_session = pending
    loop = GameLoopView(state)

    resolved = loop._resolve_lan_action(action)

    assert resolved == "open_lan_lobby"
    assert state.config.game_mode == mode_id
    assert state.lan_in_lobby is True
    assert state.net_in_lobby is True
    assert isinstance(state.net_runtime, NetRuntime)
    assert state.net_runtime is state.lan_runtime
    assert state.net_runtime.cfg.mode_id == mode_id
    assert state.net_runtime.cfg.netcode_mode == "rollback"
    if mode == "quests":
        assert state.pending_quest_level == "1.1"
