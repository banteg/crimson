from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

import typer

dbg_app = typer.Typer(add_completion=False)


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            out[key] = item
    return out


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
            chunk_ticks=chunk_ticks,
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

    impl_name = impl.strip().lower()
    if impl_name != "python":
        typer.echo("dbg record currently supports --impl python only", err=True)
        raise typer.Exit(code=2)

    profile_name = profile.strip().lower()

    try:
        summary = record_replay_to_trace(
            replay_path=Path(replay_file),
            out_path=Path(out),
            profile=profile,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            chunk_ticks=chunk_ticks,
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
                f"{str(key)}:{value}"
                for key, value in sorted(channels.items())
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


@dbg_app.command("diff")
def cmd_dbg_diff(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    policy: str = typer.Option("original_vs_python_default", "--policy", help="parity policy name"),
    float_abs_tol: float | None = typer.Option(None, "--float-abs-tol", min=0.0, help="override float abs tolerance"),
    max_field_diffs: int | None = typer.Option(
        None,
        "--max-field-diffs",
        min=1,
        help="override max field-level diffs in mismatch payloads",
    ),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Compare two traces and report the first mismatch using parity policy rules."""
    from ..dbg.diff import diff_report_to_json, diff_traces
    from ..dbg.policy import resolve_parity_policy

    try:
        parity_policy = resolve_parity_policy(
            policy,
            float_abs_tol=float_abs_tol,
            max_field_diffs=max_field_diffs,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        report = diff_traces(
            expected_trace_path=Path(golden_trace),
            actual_trace_path=Path(candidate_trace),
            policy=parity_policy,
            tick_start=tick_start,
            tick_end=tick_end,
        )
    except ValueError as exc:
        typer.echo(f"dbg diff failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload = diff_report_to_json(report)
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if report.ok:
        typer.echo(f"result=ok checked={report.checked_count} policy={report.policy}")
        return

    mismatch = report.mismatch
    assert mismatch is not None
    typer.echo(
        f"result=diverged kind={mismatch.kind} tick={mismatch.tick_index} "
        f"checked={report.checked_count} policy={report.policy}",
        err=True,
    )
    if mismatch.first_rng_mark is not None:
        typer.echo(f"first_rng_mark={mismatch.first_rng_mark}", err=True)
    for diff in mismatch.field_diffs:
        typer.echo(f"field_diff {diff.field}: expected={diff.expected!r} actual={diff.actual!r}", err=True)
    if mismatch.detail is not None:
        typer.echo("detail=" + json.dumps(mismatch.detail, sort_keys=True), err=True)
    raise typer.Exit(code=1)


@dbg_app.command("bisect")
def cmd_dbg_bisect(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    policy: str = typer.Option("original_vs_python_default", "--policy", help="parity policy name"),
    float_abs_tol: float | None = typer.Option(None, "--float-abs-tol", min=0.0, help="override float abs tolerance"),
    max_field_diffs: int | None = typer.Option(
        None,
        "--max-field-diffs",
        min=1,
        help="override max field-level diffs in mismatch payloads",
    ),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    window_before: int = typer.Option(12, "--window-before", min=0, help="ticks before first bad tick in repro trace"),
    window_after: int = typer.Option(6, "--window-after", min=0, help="ticks after first bad tick in repro trace"),
    out: Path | None = typer.Option(None, "--out", help="optional repro trace output path (.cdt)"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Bisect divergence and optionally emit a compact repro trace window."""
    from ..dbg.diff import bisect_report_to_json, bisect_traces
    from ..dbg.policy import resolve_parity_policy

    try:
        parity_policy = resolve_parity_policy(
            policy,
            float_abs_tol=float_abs_tol,
            max_field_diffs=max_field_diffs,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        report = bisect_traces(
            expected_trace_path=Path(golden_trace),
            actual_trace_path=Path(candidate_trace),
            policy=parity_policy,
            tick_start=tick_start,
            tick_end=tick_end,
            window_before=window_before,
            window_after=window_after,
            repro_out=(None if out is None else Path(out)),
        )
    except ValueError as exc:
        typer.echo(f"dbg bisect failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload = bisect_report_to_json(report)
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if report.ok:
        typer.echo(f"result=ok checked={report.checked_count} policy={report.policy}")
        return

    mismatch = report.mismatch
    assert mismatch is not None
    typer.echo(
        f"result=diverged first_bad_tick={report.first_bad_tick} "
        f"kind={mismatch.kind} checked={report.checked_count} policy={report.policy}",
    )
    if report.repro_trace_path is not None:
        typer.echo(f"repro_trace={report.repro_trace_path}")


@dbg_app.command("tick")
def cmd_dbg_tick(
    trace_file: Path = typer.Argument(..., help="trace file (.cdt)"),
    tick_index: int = typer.Argument(..., help="tick index"),
    json_mode: bool = typer.Option(False, "--json", help="print JSON payload to stdout"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Print a compact summary for one tick from a CDT trace."""
    from ..dbg.query import summarize_tick

    try:
        payload = summarize_tick(trace_path=Path(trace_file), tick_index=int(tick_index))
    except ValueError as exc:
        typer.echo(f"dbg tick failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if json_mode:
        typer.echo(json.dumps(payload, sort_keys=True))
        return

    checkpoint = _as_dict(payload.get("checkpoint"))
    rng_marks = _as_dict(payload.get("rng_marks"))
    entity_counts = _as_dict(payload.get("entity_counts"))
    top_events = payload.get("top_event_types")
    top_events_text = ",".join(str(item) for item in top_events) if isinstance(top_events, list) else ""

    typer.echo(
        "tick="
        + str(payload.get("tick_index"))
        + " elapsed_ms="
        + str(payload.get("elapsed_ms"))
        + " dt_ms_i32="
        + str(payload.get("dt_ms_i32"))
        + " mode_id="
        + str(payload.get("mode_id")),
    )
    typer.echo(
        "checkpoint "
        + "score_xp="
        + str(checkpoint.get("score_xp"))
        + " kills="
        + str(checkpoint.get("kills"))
        + " creature_count="
        + str(checkpoint.get("creature_count"))
        + " perk_pending="
        + str(checkpoint.get("perk_pending")),
    )
    typer.echo("rng_marks=" + ",".join(sorted(str(key) for key in rng_marks.keys())))
    typer.echo(
        "entity_counts "
        + "creatures="
        + str(entity_counts.get("creatures"))
        + " projectiles="
        + str(entity_counts.get("projectiles"))
        + " secondary_projectiles="
        + str(entity_counts.get("secondary_projectiles"))
        + " bonuses="
        + str(entity_counts.get("bonuses")),
    )
    typer.echo("event_count_total=" + str(payload.get("event_count_total")))
    if top_events_text:
        typer.echo("top_event_types=" + top_events_text)


@dbg_app.command("entity")
def cmd_dbg_entity(
    trace_file: Path = typer.Argument(..., help="trace file (.cdt)"),
    entity_uid: int = typer.Argument(..., help="entity uid"),
    ticks: str | None = typer.Option(None, "--ticks", help="tick range: START..END"),
    json_mode: bool = typer.Option(False, "--json", help="print JSON payload to stdout"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Trace one entity uid across ticks and print lifecycle/snapshots."""
    from ..dbg.query import entity_history, parse_tick_range

    try:
        tick_start, tick_end = parse_tick_range(ticks)
        payload = entity_history(
            trace_path=Path(trace_file),
            entity_uid=int(entity_uid),
            tick_start=tick_start,
            tick_end=tick_end,
        )
    except ValueError as exc:
        typer.echo(f"dbg entity failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if json_mode:
        typer.echo(json.dumps(payload, sort_keys=True))
        return

    samples = payload.get("samples")
    sample_rows = list(samples) if isinstance(samples, list) else []
    typer.echo(
        "uid="
        + str(payload.get("entity_uid"))
        + " pool_kind="
        + str(payload.get("pool_kind"))
        + " spawn_tick="
        + str(payload.get("spawn_tick"))
        + " despawn_tick="
        + str(payload.get("despawn_tick"))
        + " samples="
        + str(len(sample_rows)),
    )
    for item in sample_rows[:32]:
        row = _as_dict(item)
        pos = _as_dict(row.get("pos"))
        typer.echo(
            "sample "
            + "tick="
            + str(row.get("tick_index"))
            + " index="
            + str(row.get("index"))
            + " type_id="
            + str(row.get("type_id"))
            + " hp="
            + str(row.get("hp"))
            + " pos=("
            + str(pos.get("x"))
            + ","
            + str(pos.get("y"))
            + ")",
        )


@dbg_app.command("query")
def cmd_dbg_query(
    trace_file: Path = typer.Argument(..., help="trace file (.cdt)"),
    expression: str = typer.Argument(..., help="query expression, e.g. 'ticks where checkpoint.kills > 0'"),
    limit: int = typer.Option(256, "--limit", min=1, help="maximum rows included in output"),
    json_mode: bool = typer.Option(False, "--json", help="print JSON payload to stdout"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Run a small safe query DSL over tick or entity rows."""
    from ..dbg.query import query_trace

    try:
        payload = query_trace(
            trace_path=Path(trace_file),
            expression=str(expression),
            limit=int(limit),
        )
    except ValueError as exc:
        typer.echo(f"dbg query failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if json_mode:
        typer.echo(json.dumps(payload, sort_keys=True))
        return

    typer.echo(
        "scope="
        + str(payload.get("scope"))
        + " match_count="
        + str(payload.get("match_count"))
        + " truncated="
        + str(payload.get("truncated")),
    )
    rows_obj = payload.get("rows")
    rows = list(rows_obj) if isinstance(rows_obj, list) else []
    for row in rows[:32]:
        typer.echo("row=" + json.dumps(row, sort_keys=True))


@dbg_app.command("focus")
def cmd_dbg_focus(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    tick: int = typer.Option(..., "--tick", help="focus tick index"),
    policy: str = typer.Option("original_vs_python_default", "--policy", help="parity policy name"),
    float_abs_tol: float | None = typer.Option(None, "--float-abs-tol", min=0.0, help="override float abs tolerance"),
    max_field_diffs: int | None = typer.Option(
        None,
        "--max-field-diffs",
        min=1,
        help="override max field-level diffs in checkpoint payload",
    ),
    json_mode: bool = typer.Option(False, "--json", help="print JSON payload to stdout"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Generate a focused side-by-side report for one tick."""
    from ..dbg.focus import focus_tick
    from ..dbg.policy import resolve_parity_policy

    try:
        parity_policy = resolve_parity_policy(
            policy,
            float_abs_tol=float_abs_tol,
            max_field_diffs=max_field_diffs,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        payload = focus_tick(
            golden_trace=Path(golden_trace),
            candidate_trace=Path(candidate_trace),
            tick_index=tick,
            policy=parity_policy,
        )
    except ValueError as exc:
        typer.echo(f"dbg focus failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if json_mode:
        typer.echo(json.dumps(payload, sort_keys=True))
        return

    result = "diverged" if bool(payload.get("diverged")) else "ok"
    typer.echo(
        "result="
        + result
        + " tick="
        + str(payload.get("tick_index"))
        + " policy="
        + str(payload.get("policy"))
        + " checkpoint_field_count="
        + str(payload.get("checkpoint_field_count")),
    )
    rng_marks = _as_dict(payload.get("rng_marks"))
    typer.echo("first_rng_mark=" + str(rng_marks.get("first_mismatch_mark")))
    rng_stream = _as_dict(payload.get("rng_stream"))
    typer.echo(
        "rng_stream "
        + "prefix_match_len="
        + str(rng_stream.get("prefix_match_len"))
        + " missing_tail="
        + str(rng_stream.get("missing_tail"))
        + " extra_tail="
        + str(rng_stream.get("extra_tail")),
    )
    event_heads = _as_dict(payload.get("event_heads"))
    typer.echo(
        "event_heads "
        + "expected_count="
        + str(event_heads.get("expected_count"))
        + " candidate_count="
        + str(event_heads.get("candidate_count")),
    )


@dbg_app.command("viz")
def cmd_dbg_viz(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    tick: int | None = typer.Option(None, "--tick", help="focus tick (auto when omitted)"),
    policy: str = typer.Option("original_vs_python_default", "--policy", help="parity policy name"),
    window_before: int = typer.Option(64, "--window-before", min=0, help="ticks before focus tick"),
    window_after: int = typer.Option(64, "--window-after", min=0, help="ticks after focus tick"),
    out: Path | None = typer.Option(None, "--out", help="output HTML path"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON summary output path"),
) -> None:
    """Render a static HTML divergence timeline around a focus tick."""
    from ..dbg.policy import resolve_parity_policy
    from ..dbg.viz import write_viz_html

    try:
        parity_policy = resolve_parity_policy(policy)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    html_out = Path(out) if out is not None else Path(candidate_trace).with_suffix(".viz.html")

    try:
        payload = write_viz_html(
            golden_trace=Path(golden_trace),
            candidate_trace=Path(candidate_trace),
            policy=parity_policy,
            tick=tick,
            window_before=window_before,
            window_after=window_after,
            out_path=html_out,
        )
    except ValueError as exc:
        typer.echo(f"dbg viz failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    typer.echo(
        "viz_html="
        + str(payload.get("html_path"))
        + " focus_tick="
        + str(payload.get("focus_tick"))
        + " rows="
        + str(payload.get("row_count")),
    )
