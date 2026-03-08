from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..quests.level import QuestLevel
from .lockstep_protocol import StatusSnapshot
from .lockstep_runtime import (
    HostLockstepRuntime,
    HostLockstepRuntimeConfig,
    JoinLockstepRuntime,
    JoinLockstepRuntimeConfig,
    LockstepRuntime,
)
from .rollback_runtime import (
    HostRollbackRuntimeConfig,
    JoinRollbackRuntimeConfig,
    RollbackRuntime,
)

if TYPE_CHECKING:
    from ..game.types import PendingNetworkSession

NetworkRuntime = RollbackRuntime | LockstepRuntime


@dataclass(frozen=True, slots=True)
class BuiltNetworkRuntime:
    runtime: NetworkRuntime
    mode_id: GameMode
    player_count: int
    quest_level: QuestLevel | None
    netcode_mode: str


def _mode_id_for_pending_session(pending: PendingNetworkSession) -> GameMode:
    mode = str(pending.config.mode)
    if mode == "survival":
        return GameMode.SURVIVAL
    if mode == "rush":
        return GameMode.RUSH
    if mode == "quests":
        return GameMode.QUESTS
    raise ValueError(f"Unsupported LAN mode: {mode!r}")


def build_network_runtime(
    pending: PendingNetworkSession,
    *,
    sim_status_snapshot: StatusSnapshot | None,
) -> BuiltNetworkRuntime:
    from ..game.types import LockstepEndpoint, RollbackEndpoint

    cfg = pending.config
    mode_id = _mode_id_for_pending_session(pending)
    player_count = max(1, min(4, int(cfg.player_count)))
    if mode_id == GameMode.QUESTS and cfg.quest_level is None:
        raise ValueError("Quest LAN mode requires --quest-level.")

    if cfg.netcode_mode == "lockstep":
        endpoint = cfg.endpoint
        assert isinstance(endpoint, LockstepEndpoint), "lockstep sessions require a LockstepEndpoint"
        if pending.role == "host":
            runtime: NetworkRuntime = HostLockstepRuntime(
                HostLockstepRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    bind_host=str(endpoint.bind_host),
                    host_ip=str(endpoint.host),
                    port=int(endpoint.port),
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )
        else:
            runtime = JoinLockstepRuntime(
                JoinLockstepRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    bind_host=str(endpoint.bind_host),
                    host_ip=str(endpoint.host),
                    port=int(endpoint.port),
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )
    else:
        endpoint = cfg.endpoint
        assert isinstance(endpoint, RollbackEndpoint), "rollback sessions require a RollbackEndpoint"
        if pending.role == "host":
            runtime = RollbackRuntime(
                HostRollbackRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    relay_host=str(endpoint.relay_host),
                    relay_port=int(endpoint.relay_port),
                    room_code=endpoint.room_code,
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    netcode_mode="rollback",
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    rollback_max_ticks=max(1, int(cfg.rollback_max_ticks)),
                    reconnect_timeout_ms=max(1000, int(cfg.reconnect_timeout_ms)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )
        else:
            runtime = RollbackRuntime(
                JoinRollbackRuntimeConfig(
                    mode_id=mode_id,
                    player_count=int(player_count),
                    relay_host=str(endpoint.relay_host),
                    relay_port=int(endpoint.relay_port),
                    room_code=endpoint.room_code,
                    quest_level=cfg.quest_level,
                    preserve_bugs=False,
                    netcode_mode="rollback",
                    input_delay_ticks=max(0, int(cfg.input_delay_ticks)),
                    rollback_max_ticks=max(1, int(cfg.rollback_max_ticks)),
                    reconnect_timeout_ms=max(1000, int(cfg.reconnect_timeout_ms)),
                    sim_status_snapshot=sim_status_snapshot,
                ),
            )

    return BuiltNetworkRuntime(
        runtime=runtime,
        mode_id=mode_id,
        player_count=int(player_count),
        quest_level=cfg.quest_level,
        netcode_mode=str(cfg.netcode_mode),
    )


__all__ = ["BuiltNetworkRuntime", "NetworkRuntime", "build_network_runtime"]
