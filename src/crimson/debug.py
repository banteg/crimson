from __future__ import annotations

import os

_DEBUG_OVERRIDE: bool | None = None


def set_debug_enabled(enabled: bool) -> None:
    global _DEBUG_OVERRIDE
    _DEBUG_OVERRIDE = bool(enabled)


def debug_enabled() -> bool:
    if _DEBUG_OVERRIDE is not None:
        return bool(_DEBUG_OVERRIDE)
    return os.environ.get("CRIMSON_DEBUG") == "1"
