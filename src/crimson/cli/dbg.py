from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

import typer

dbg_app = typer.Typer(add_completion=False)


def _int_like(value: object) -> int:
    try:
        return int(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return 0


@dbg_app.command("import-capture")
def cmd_dbg_import_capture(
    capture_file: Path = typer.Argument(..., help="capture file (.json/.json.gz/.msgpack.zst)"),
    out: Path = typer.Option(..., "--out", help="output trace path (.cdt)"),
    chunk_ticks: int = typer.Option(256, "--chunk-ticks", min=1, help="ticks per compressed CDT block"),
) -> None:
    """Convert an original capture into Crimson Debug Trace (CDT)."""
    from ..dbg.import_capture import import_capture_to_trace
    from ..dbg.trace import TraceError

    try:
        summary = import_capture_to_trace(
            capture_path=Path(capture_file),
            out_path=Path(out),
            chunk_ticks=int(chunk_ticks),
        )
    except (TraceError, ValueError) as exc:
        typer.echo(f"dbg import-capture failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    tick_range = summary.meta.tick_range
    typer.echo(f"trace={out}")
    typer.echo(
        "ticks "
        f"start={tick_range.get('start_tick')} "
        f"end={tick_range.get('end_tick')} "
        f"count={tick_range.get('tick_count')}",
    )
    typer.echo("channels=" + ",".join(summary.meta.channels))


@dbg_app.command("record")
def cmd_dbg_record(
    replay_file: Path = typer.Argument(..., help="replay file (.crd)"),
    out: Path = typer.Option(..., "--out", help="output trace path (.cdt)"),
    impl: str = typer.Option("python", "--impl", help="trace producer implementation id (v1 supports: python)"),
    profile: Literal["minimal", "standard", "full"] = typer.Option("standard", "--profile", help="minimal|standard|full"),
    max_ticks: int | None = typer.Option(None, "--max-ticks", min=0, help="optional replay tick cap"),
    strict_events: bool = typer.Option(
        True,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: strict)",
    ),
    chunk_ticks: int = typer.Option(256, "--chunk-ticks", min=1, help="ticks per compressed CDT block"),
) -> None:
    """Run replay simulation and record a CDT trace."""
    from ..dbg.record import record_replay_to_trace
    from ..dbg.trace import TraceError

    impl_name = str(impl).strip().lower()
    if impl_name != "python":
        typer.echo("dbg record currently supports --impl python only", err=True)
        raise typer.Exit(code=2)

    profile_name = str(profile).strip().lower()

    try:
        summary = record_replay_to_trace(
            replay_path=Path(replay_file),
            out_path=Path(out),
            profile=profile,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            chunk_ticks=int(chunk_ticks),
        )
    except (TraceError, ValueError) as exc:
        typer.echo(f"dbg record failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    tick_range = summary.meta.tick_range
    typer.echo(f"trace={out}")
    typer.echo(f"profile={profile_name}")
    typer.echo(
        "ticks "
        f"start={tick_range.get('start_tick')} "
        f"end={tick_range.get('end_tick')} "
        f"count={tick_range.get('tick_count')}",
    )
    typer.echo("channels=" + ",".join(summary.meta.channels))


@dbg_app.command("health")
def cmd_dbg_health(
    trace_file: Path = typer.Argument(..., help="trace file (.cdt)"),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    strict: bool = typer.Option(False, "--strict", help="exit non-zero when required debug channels are missing"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Summarize CDT telemetry coverage and channel availability."""
    from ..dbg.health import summarize_trace_health
    from ..dbg.trace import TraceError

    try:
        summary = summarize_trace_health(
            Path(trace_file),
            tick_start=tick_start,
            tick_end=tick_end,
        )
    except TraceError as exc:
        typer.echo(f"dbg health failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    tick_window_obj = summary.get("tick_window")
    tick_window: dict[str, object] = (
        cast("dict[str, object]", tick_window_obj) if isinstance(tick_window_obj, dict) else {}
    )
    metrics_obj = summary.get("metrics")
    metrics: dict[str, object] = cast("dict[str, object]", metrics_obj) if isinstance(metrics_obj, dict) else {}
    channels_obj = summary.get("channels_present")
    channels: dict[str, object] = cast("dict[str, object]", channels_obj) if isinstance(channels_obj, dict) else {}
    issues_obj = summary.get("issues")
    issues = [str(item) for item in issues_obj] if isinstance(issues_obj, list) else []
    ok = bool(summary.get("ok_for_movement_root_cause"))

    typer.echo(f"trace={trace_file}")
    typer.echo(f"trace_format_version={summary.get('trace_format_version')}")
    typer.echo(f"trace_schema_version={summary.get('trace_schema_version')}")
    typer.echo(
        "tick_window "
        f"requested_start={tick_window.get('requested_start')} "
        f"requested_end={tick_window.get('requested_end')} "
        f"actual_start={tick_window.get('actual_start')} "
        f"actual_end={tick_window.get('actual_end')} "
        f"ticks_in_window={tick_window.get('ticks_in_window')}",
    )
    typer.echo(
        "channels="
        + (
            ",".join(
                f"{str(key)}:{_int_like(value)}"
                for key, value in sorted(channels.items(), key=lambda item: str(item[0]))
            )
            if channels
            else "(none)"
        ),
    )
    metric_keys = (
        "ticks_with_dt_ms_i32",
        "rng_stream_head_rows",
        "event_head_rows",
        "micro_trace_rows",
        "sample_creature_rows",
        "sample_projectile_rows",
        "sample_secondary_projectile_rows",
        "sample_bonus_rows",
    )
    for key in metric_keys:
        typer.echo(f"{key}={metrics.get(key)}")
    typer.echo(f"movement_root_cause_ready={ok}")
    for issue in issues:
        typer.echo(f"issue={issue}")

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if bool(strict) and not bool(ok):
        raise typer.Exit(code=1)
