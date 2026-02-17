from __future__ import annotations

# Compatibility re-export.
from .legacy_runtime import *  # noqa: F401,F403
from .legacy_runtime import IDLE_HEARTBEAT_MS, PAUSED_LINK_TIMEOUT_MS, LanRuntime, LanRuntimeConfig

__all__ = ["IDLE_HEARTBEAT_MS", "PAUSED_LINK_TIMEOUT_MS", "LanRuntime", "LanRuntimeConfig"]
