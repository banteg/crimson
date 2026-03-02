from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.types import LockstepEndpoint, NetworkSessionConfig, PendingNetworkSession, RollbackEndpoint
from crimson.net.lockstep_runtime import LockstepRuntime


def test_manual_lockstep_fallback_selects_lockstep_runtime(make_game_state) -> None:
    state = make_game_state()
    pending = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="survival",
            netcode_mode="lockstep",
            endpoint=LockstepEndpoint(
                bind_host="0.0.0.0",
                host="127.0.0.1",
                port=31993,
            ),
            player_count=2,
            quest_level="",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_network_session = pending
    loop = GameLoopView(state)

    resolved = loop._resolve_lan_action("start_survival_lan")

    assert resolved == "open_lan_lobby"
    assert isinstance(state.network_runtime, LockstepRuntime)
    assert state.network_in_lobby is True


def test_fallback_netcode_mode_is_not_switched_mid_match(make_game_state) -> None:
    state = make_game_state()
    pending = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode="survival",
            netcode_mode="lockstep",
            endpoint=LockstepEndpoint(
                bind_host="0.0.0.0",
                host="127.0.0.1",
                port=31993,
            ),
            player_count=2,
            quest_level="",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_network_session = pending
    loop = GameLoopView(state)
    assert loop._resolve_lan_action("start_survival_lan") == "open_lan_lobby"

    runtime = state.network_runtime
    assert isinstance(runtime, LockstepRuntime)

    # Gameplay transition from lobby keeps the existing runtime instance.
    pending.config = NetworkSessionConfig(
        mode="survival",
        netcode_mode="rollback",
        endpoint=RollbackEndpoint(
            relay_host="127.0.0.1",
            relay_port=31993,
            room_code="",
        ),
        player_count=2,
        quest_level="",
        rollback_max_ticks=8,
        reconnect_timeout_ms=15_000,
        input_delay_ticks=1,
        preserve_bugs=False,
    )
    assert loop._resolve_lan_action("start_survival") == "start_survival"
    assert state.network_runtime is runtime
    assert isinstance(state.network_runtime, LockstepRuntime)
