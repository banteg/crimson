from __future__ import annotations

from enum import Enum


class RtxRenderMode(str, Enum):
    CLASSIC = "classic"
    RTX = "rtx"


def parse_rtx_render_mode(raw: str) -> RtxRenderMode:
    value = str(raw).strip().lower()
    if value == "classic":
        return RtxRenderMode.CLASSIC
    if value == "rtx":
        return RtxRenderMode.RTX
    raise ValueError(f"unsupported render mode {raw!r}; expected classic|rtx")


def mode_from_rtx_flag(enabled: bool) -> RtxRenderMode:
    if bool(enabled):
        return RtxRenderMode.RTX
    return RtxRenderMode.CLASSIC


def cycle_rtx_render_mode(mode: RtxRenderMode) -> RtxRenderMode:
    if mode is RtxRenderMode.RTX:
        return RtxRenderMode.CLASSIC
    return RtxRenderMode.RTX


__all__ = [
    "RtxRenderMode",
    "cycle_rtx_render_mode",
    "mode_from_rtx_flag",
    "parse_rtx_render_mode",
]
