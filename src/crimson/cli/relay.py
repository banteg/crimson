from __future__ import annotations

from pathlib import Path

import typer

from ..paths import default_runtime_dir

relay_app = typer.Typer(add_completion=False)
@relay_app.command("serve")
def cmd_relay_serve(
    bind: str = typer.Option("0.0.0.0", "--bind", help="relay bind address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="relay UDP port"),
    tick_ms: int = typer.Option(8, "--tick-ms", min=1, max=1000, help="relay update tick interval"),
    log_level: str = typer.Option("debug", "--log-level", help="relay log level (debug|info|warning|error)"),
    log_file: Path | None = typer.Option(
        None,
        "--log-file",
        help="relay log file path (default: runtime-dir/logs/relay/relay-<pid>-<ts>.log)",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for relay logs (default: per-user OS data dir)",
    ),
) -> None:
    """Serve the in-repo UDP relay."""
    from ..logging import configure_component_logging, default_component_log_path
    from ..net.relay_service import RelayServer, RelayServerConfig

    resolved_log_file = (
        Path(log_file).expanduser()
        if log_file is not None
        else default_component_log_path(base_dir=base_dir, component="relay")
    )
    try:
        configured_log_file = configure_component_logging(
            logger_name="crimson.relay",
            component="relay",
            log_file=resolved_log_file,
            level=log_level,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--log-level") from exc
    typer.echo(f"relay logs -> {configured_log_file}")

    server = RelayServer(
        RelayServerConfig(
            bind_host=str(bind).strip() or "0.0.0.0",
            bind_port=int(port),
        ),
    )
    server.serve_forever(tick_ms=max(1, int(tick_ms)))


