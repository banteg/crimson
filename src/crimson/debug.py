from __future__ import annotations

import os


def debug_enabled() -> bool:
    return os.environ.get("CRIMSON_DEBUG") == "1"
