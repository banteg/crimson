from __future__ import annotations

from grim.math import clamp

_RAD_TO_DEG = 57.29577951308232


def monster_vision_fade_alpha(lifecycle_stage: float) -> float:
    if float(lifecycle_stage) >= 0.0:
        return 1.0
    return clamp((float(lifecycle_stage) + 10.0) * 0.1, 0.0, 1.0)


__all__ = ["_RAD_TO_DEG", "monster_vision_fade_alpha"]
