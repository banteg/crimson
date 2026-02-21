from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer

_SessionMode = Literal["survival", "rush", "quests"]
_ParsedNetcodeMode = Literal["rollback", "lockstep_legacy"]


def _parse_session_mode(mode: str) -> _SessionMode:
    mode_name = str(mode).strip().lower()
    if mode_name == "survival":
        return "survival"
    if mode_name == "rush":
        return "rush"
    if mode_name == "quests":
        return "quests"
    raise typer.BadParameter(
        f"unsupported mode {mode!r}; expected one of: survival, rush, quests",
        param_hint="--mode",
    )


def _parse_netcode_mode(raw: str) -> _ParsedNetcodeMode:
    value = str(raw).strip().lower()
    if value in {"rollback", "rb"}:
        return "rollback"
    if value in {"lockstep", "lockstep_legacy", "legacy"}:
        return "lockstep_legacy"
    raise typer.BadParameter(
        f"unsupported netcode {raw!r}; expected rollback|lockstep",
        param_hint="--netcode",
    )


def _run_game_with_pending_session(
    *,
    pending,
    base_dir: Path,
    assets_dir: Path | None,
    width: int | None,
    height: int | None,
    fps: int,
    debug: bool,
) -> None:
    from ..game import GameConfig, run_game

    run_game(
        GameConfig(
            base_dir=base_dir,
            assets_dir=assets_dir,
            width=width,
            height=height,
            fps=fps,
            debug=bool(debug),
            preserve_bugs=False,
            pending_net_session=pending,
            pending_lan_session=pending,
        ),
    )
