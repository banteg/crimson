from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game.types import (
    FrontRouteId,
    NetworkSessionConfig,
    NetworkSessionMode,
    PendingNetworkSession,
    RollbackEndpoint,
)
from crimson.game_modes import GameMode
from crimson.net.rollback_runtime import RollbackRuntime
from crimson.quests.level import QuestLevel


@pytest.mark.parametrize(
    ("mode", "route", "mode_id", "quest_level"),
    [
        ("survival", FrontRouteId.START_SURVIVAL, int(GameMode.SURVIVAL), None),
        ("rush", FrontRouteId.START_RUSH, int(GameMode.RUSH), None),
        ("quests", FrontRouteId.START_QUEST, int(GameMode.QUESTS), QuestLevel(1, 1)),
    ],
)
def test_rollback_runtime_is_selected_for_all_network_modes(
    make_game_state,
    mode: NetworkSessionMode,
    route: FrontRouteId,
    mode_id: int,
    quest_level: QuestLevel | None,
) -> None:
    state = make_game_state()
    pending = PendingNetworkSession(
        role="host",
        config=NetworkSessionConfig(
            mode=mode,
            endpoint=RollbackEndpoint(
                relay_host="127.0.0.1",
                relay_port=31993,
                room_code=None,
            ),
            netcode_mode="rollback",
            player_count=2,
            quest_level=quest_level,
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=False,
    )
    state.pending_network_session = pending
    loop = GameLoopView(state)

    loop._prepare_lan_lobby(route)
    assert state.config.game_mode == mode_id
    assert state.network_in_lobby is True
    assert isinstance(state.network_runtime, RollbackRuntime)
    assert state.network_runtime.cfg.mode_id == mode_id
    assert state.network_runtime.cfg.netcode_mode == "rollback"
    if mode == "quests":
        assert state.pending_quest_level == QuestLevel(1, 1)
