from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.types import LanSessionConfig, PendingLanSession
from crimson.net.runtime import LanRuntime


def test_manual_lockstep_fallback_selects_legacy_runtime(make_game_state) -> None:
    state = make_game_state()
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="survival",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="lockstep_legacy",
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

    resolved = loop._resolve_lan_action("start_survival_lan")

    assert resolved == "open_lan_lobby"
    assert isinstance(state.net_runtime, LanRuntime)
    assert state.net_runtime is state.lan_runtime
    assert state.lan_in_lobby is True
    assert state.net_in_lobby is True


def test_fallback_netcode_mode_is_not_switched_mid_match(make_game_state) -> None:
    state = make_game_state()
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode="survival",
            player_count=2,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
            host_ip="127.0.0.1",
            port=31993,
            netcode_mode="lockstep_legacy",
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
    assert loop._resolve_lan_action("start_survival_lan") == "open_lan_lobby"

    runtime = state.net_runtime
    assert isinstance(runtime, LanRuntime)

    # Gameplay transition from lobby keeps the existing runtime instance.
    pending.config = LanSessionConfig(
        mode="survival",
        player_count=2,
        quest_level="",
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
    )
    assert loop._resolve_lan_action("start_survival") == "start_survival"
    assert state.net_runtime is runtime
    assert isinstance(state.net_runtime, LanRuntime)
