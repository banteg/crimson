from __future__ import annotations

_NATIVE_FIND_SIZE_MARGIN_SCALE = 0.14285715
_NATIVE_FIND_SIZE_MARGIN_BIAS = 3.0


def native_find_size_margin(target_size: float) -> float:
    """Native collision threshold term used by `*_find_in_radius` routines."""

    return float(target_size) * _NATIVE_FIND_SIZE_MARGIN_SCALE + _NATIVE_FIND_SIZE_MARGIN_BIAS


__all__ = ["native_find_size_margin"]
