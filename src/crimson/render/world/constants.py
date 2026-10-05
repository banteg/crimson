from __future__ import annotations

from grim.math import clamp

_RAD_TO_DEG = 57.29577951308232


def monster_vision_fade_alpha(death_timer: float) -> float:
    if float(death_timer) >= 0.0:
        return 1.0
    return clamp((float(death_timer) + 10.0) * 0.1, 0.0, 1.0)


__all__ = ["_RAD_TO_DEG", "monster_vision_fade_alpha"]
