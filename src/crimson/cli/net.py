from __future__ import annotations

from pathlib import Path

import typer

from ..paths import default_runtime_dir
from .session import _parse_netcode_mode, _parse_session_mode, _run_game_with_pending_session

net_app = typer.Typer(add_completion=False)
@net_app.command("host")
def cmd_net_host(
    mode: str = typer.Option(..., "--mode", help="survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor (required for quests mode)"),
    players: int = typer.Option(..., "--players", min=1, max=4, help="player count (1..4)"),
    bind: str = typer.Option("0.0.0.0", "--bind", help="local bind address"),
    relay_host: str = typer.Option("127.0.0.1", "--relay-host", help="relay host or IP"),
    relay_port: int = typer.Option(31993, "--relay-port", min=1, max=65535, help="relay UDP port"),
    room_code: str = typer.Option("", "--room-code", help="optional room code override"),
    netcode: str = typer.Option("rollback", "--netcode", help="rollback|lockstep"),
    rollback_max_ticks: int = typer.Option(8, "--rollback-max-ticks", min=1, max=64, help="rollback cap ticks"),
    reconnect_timeout_ms: int = typer.Option(
        15_000,
        "--reconnect-timeout-ms",
        min=1_000,
        max=120_000,
        help="reconnect timeout in milliseconds",
    ),
    input_delay_ticks: int = typer.Option(1, "--input-delay-ticks", min=0, max=8, help="local input delay"),
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
    """Host a network session (rollback default)."""
    from ..game.types import LanSessionConfig, PendingLanSession
    from ..quests.types import parse_level

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
            relay_host=str(relay_host).strip() or "127.0.0.1",
            relay_port=int(relay_port),
            room_code=str(room_code).strip().upper(),
            host_ip=str(relay_host).strip() or "127.0.0.1",
            port=int(relay_port),
            netcode_mode=_parse_netcode_mode(netcode),
            rollback_max_ticks=int(rollback_max_ticks),
            reconnect_timeout_ms=int(reconnect_timeout_ms),
            input_delay_ticks=int(input_delay_ticks),
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


@net_app.command("join")
def cmd_net_join(
    code: str = typer.Option(..., "--code", help="invite room code"),
    mode: str = typer.Option("survival", "--mode", help="expected mode: survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor"),
    relay_host: str = typer.Option("127.0.0.1", "--relay-host", help="relay host or IP"),
    relay_port: int = typer.Option(31993, "--relay-port", min=1, max=65535, help="relay UDP port"),
    netcode: str = typer.Option("rollback", "--netcode", help="rollback|lockstep"),
    rollback_max_ticks: int = typer.Option(8, "--rollback-max-ticks", min=1, max=64, help="rollback cap ticks"),
    reconnect_timeout_ms: int = typer.Option(
        15_000,
        "--reconnect-timeout-ms",
        min=1_000,
        max=120_000,
        help="reconnect timeout in milliseconds",
    ),
    input_delay_ticks: int = typer.Option(1, "--input-delay-ticks", min=0, max=8, help="local input delay"),
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
    """Join a network session via invite room code."""
    from ..game.types import LanSessionConfig, PendingLanSession

    room_code = str(code).strip().upper()
    if not room_code:
        raise typer.BadParameter("room code is required", param_hint="--code")
    pending = PendingLanSession(
        role="join",
        config=LanSessionConfig(
            mode=_parse_session_mode(mode),
            player_count=1,
            quest_level=str(quest_level).strip(),
            bind_host="0.0.0.0",
            relay_host=str(relay_host).strip() or "127.0.0.1",
            relay_port=int(relay_port),
            room_code=room_code,
            host_ip=str(relay_host).strip() or "127.0.0.1",
            port=int(relay_port),
            netcode_mode=_parse_netcode_mode(netcode),
            rollback_max_ticks=int(rollback_max_ticks),
            reconnect_timeout_ms=int(reconnect_timeout_ms),
            input_delay_ticks=int(input_delay_ticks),
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

