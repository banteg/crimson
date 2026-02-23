from __future__ import annotations

from pathlib import Path

import typer

from ..paths import default_runtime_dir
from .session import _parse_session_mode, _run_game_with_pending_session

lan_app = typer.Typer(add_completion=False)
@lan_app.command("host")
def cmd_lan_host(
    mode: str = typer.Option(..., "--mode", help="survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor (required for quests mode)"),
    players: int = typer.Option(..., "--players", min=1, max=4, help="player count (1..4)"),
    bind: str = typer.Option("0.0.0.0", "--bind", help="host bind address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="host UDP port"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
    rtx: bool = typer.Option(False, "--rtx", help="enable non-canonical RTX render mode"),
    width: int | None = typer.Option(None, help="window width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="window height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, help="target fps"),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
    assets_dir: Path | None = typer.Option(
        None,
        help="assets root (default: base-dir; missing .paq files are downloaded)",
    ),
) -> None:
    """Deprecated wrapper for `net host`."""
    from ..game.types import LanSessionConfig, PendingLanSession
    from ..quests.types import parse_level

    typer.echo("warning: `crimson lan host` is deprecated; use `crimson net host`.", err=True)
    resolved_mode = _parse_session_mode(mode)
    normalized_quest_level = str(quest_level).strip()
    if resolved_mode == "quests":
        if not normalized_quest_level:
            raise typer.BadParameter("quest level is required for quests mode", param_hint="--quest-level")
        try:
            parse_level(normalized_quest_level)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--quest-level") from exc
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode=resolved_mode,
            player_count=int(players),
            quest_level=normalized_quest_level,
            bind_host=str(bind).strip() or "0.0.0.0",
            relay_host=str(bind).strip() or "127.0.0.1",
            relay_port=int(port),
            room_code="",
            host_ip="",
            port=int(port),
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
        rtx=bool(rtx),
    )


@lan_app.command("join")
def cmd_lan_join(
    host: str = typer.Option(..., "--host", help="host IP address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="host UDP port"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
    rtx: bool = typer.Option(False, "--rtx", help="enable non-canonical RTX render mode"),
    width: int | None = typer.Option(None, help="window width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="window height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, help="target fps"),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
    assets_dir: Path | None = typer.Option(
        None,
        help="assets root (default: base-dir; missing .paq files are downloaded)",
    ),
) -> None:
    """Deprecated wrapper for `net join`."""
    from ..game.types import LanSessionConfig, PendingLanSession

    typer.echo("warning: `crimson lan join` is deprecated; use `crimson net join --code`.", err=True)
    host_ip = str(host).strip()
    if not host_ip:
        raise typer.BadParameter("host address is required", param_hint="--host")
    pending = PendingLanSession(
        role="join",
        config=LanSessionConfig(
            mode="survival",
            player_count=1,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host=host_ip,
            relay_port=int(port),
            room_code="",
            host_ip=host_ip,
            port=int(port),
            netcode_mode="lockstep_legacy",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
        rtx=bool(rtx),
    )

