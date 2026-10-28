from __future__ import annotations

from enum import Enum
from pathlib import Path

# The player's choice of mode, in the runtime folder the native client shares (crimson-core/game/rtx.cpp).
RTX_CHOICE_NAME = "render_mode.txt"


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
    if enabled:
        return RtxRenderMode.RTX
    return RtxRenderMode.CLASSIC


def cycle_rtx_render_mode(mode: RtxRenderMode) -> RtxRenderMode:
    if mode is RtxRenderMode.RTX:
        return RtxRenderMode.CLASSIC
    return RtxRenderMode.RTX


def load_rtx_choice(base_dir: Path) -> RtxRenderMode:
    path = base_dir / RTX_CHOICE_NAME
    return mode_from_rtx_flag(path.is_file() and path.read_bytes().startswith(b"rtx"))


def save_rtx_choice(base_dir: Path, mode: RtxRenderMode) -> None:
    (base_dir / RTX_CHOICE_NAME).write_text(f"{mode.value}\n")


__all__ = [
    "RTX_CHOICE_NAME",
    "RtxRenderMode",
    "cycle_rtx_render_mode",
    "load_rtx_choice",
    "mode_from_rtx_flag",
    "parse_rtx_render_mode",
    "save_rtx_choice",
]
