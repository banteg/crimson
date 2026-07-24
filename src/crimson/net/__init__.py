from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .adapter import ClientLanAdapter, HostLanAdapter
    from .lockstep_lobby import ClientLobby, HostLobby
    from .lockstep_runtime import LockstepRuntime, LockstepRuntimeConfig
    from .lockstep_state import ClientLockstepState, HostLockstepState
    from .relay_service import RelayServer, RelayServerConfig
    from .reliable import ReliableLink
    from .resync import ResyncAssembler, ResyncBuildError
    from .rollback_runtime import RollbackRuntime, RollbackRuntimeConfig
    from .transport import PeerAddr, UdpTransport

__all__ = [
    "ClientLanAdapter",
    "ClientLobby",
    "ClientLockstepState",
    "DEFAULT_PORT",
    "HostLanAdapter",
    "HostLobby",
    "HostLockstepState",
    "INPUT_DELAY_TICKS",
    "LockstepRuntime",
    "LockstepRuntimeConfig",
    "MAX_PLAYERS",
    "RollbackRuntime",
    "RollbackRuntimeConfig",
    "PROTOCOL_VERSION",
    "PeerAddr",
    "RELIABLE_RESEND_MS",
    "ReliableLink",
    "RelayServer",
    "RelayServerConfig",
    "ResyncAssembler",
    "ResyncBuildError",
    "TICK_RATE",
    "UdpTransport",
    "build_resync_messages",
]

_EXPORT_MODULES = {
    "ClientLanAdapter": ".adapter",
    "HostLanAdapter": ".adapter",
    "ClientLobby": ".lockstep_lobby",
    "HostLobby": ".lockstep_lobby",
    "DEFAULT_PORT": ".lockstep_protocol",
    "INPUT_DELAY_TICKS": ".lockstep_protocol",
    "MAX_PLAYERS": ".lockstep_protocol",
    "PROTOCOL_VERSION": ".lockstep_protocol",
    "RELIABLE_RESEND_MS": ".lockstep_protocol",
    "TICK_RATE": ".lockstep_protocol",
    "LockstepRuntime": ".lockstep_runtime",
    "LockstepRuntimeConfig": ".lockstep_runtime",
    "ClientLockstepState": ".lockstep_state",
    "HostLockstepState": ".lockstep_state",
    "RelayServer": ".relay_service",
    "RelayServerConfig": ".relay_service",
    "ReliableLink": ".reliable",
    "ResyncAssembler": ".resync",
    "ResyncBuildError": ".resync",
    "build_resync_messages": ".resync",
    "RollbackRuntime": ".rollback_runtime",
    "RollbackRuntimeConfig": ".rollback_runtime",
    "PeerAddr": ".transport",
    "UdpTransport": ".transport",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value
