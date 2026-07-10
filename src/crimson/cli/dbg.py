from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

import typer

from ..dbg.payloads import BuiltinObject, builtin_object_or_empty, coerce_builtin_value

dbg_app = typer.Typer(add_completion=False)


def _as_dict(value: object) -> BuiltinObject:
    if not isinstance(value, dict):
        return {}
    out: BuiltinObject = {}
    for key, item in value.items():
        if isinstance(key, str):
            try:
                out[key] = coerce_builtin_value(item, field=f"payload.{key}")
            except TypeError:
                continue
    return out


def _first_diff_path(detail: BuiltinObject | None) -> str | None:
    if not detail:
        return None
    candidates: list[object] = []
    candidates.append(detail.get("mismatches"))
    payload = detail.get("payload")
    if isinstance(payload, dict):
        candidates.append(payload.get("mismatches"))
    row_diffs = detail.get("row_diffs")
    if isinstance(row_diffs, list) and row_diffs and isinstance(row_diffs[0], dict):
        candidates.append(row_diffs[0].get("mismatches"))
    for rows in candidates:
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            row = cast("dict[str, object]", rows[0])
            path = row.get("path")
            if isinstance(path, str):
                return path
    return None


@dbg_app.command("record")
def cmd_dbg_record(
    replay_file: Path = typer.Argument(..., help="replay file (.crd)"),
    out: Path = typer.Option(..., "--out", help="output trace path (.cdt)"),
    impl: Literal["python", "zig"] = typer.Option(
        "python",
        "--impl",
        help="recording backend implementation",
    ),
) -> None:
    """Run replay simulation and record a CDT trace."""
    from ..dbg.record import record_replay_to_trace
    from ..dbg.trace import TraceError
    from ..replay.driver.setup import ReplayRunnerError

    warnings_out: list[str] = []
    try:
        summary = record_replay_to_trace(
            replay_path=Path(replay_file),
            out_path=Path(out),
            impl=impl,
            warnings_out=warnings_out,
        )
    except (TraceError, ValueError, ReplayRunnerError) as exc:
        typer.echo(f"dbg record failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    for warning in warnings_out:
        typer.echo(str(warning), err=True)
    tick_range = summary.meta.tick_range
    typer.echo(f"trace={out}")
    typer.echo(
        "ticks "
        f"start={tick_range.start_tick} "
        f"end={tick_range.end_tick} "
        f"count={tick_range.tick_count}",
    )
    from ..dbg.schema import TRACE_REQUIRED_CHANNELS

    typer.echo("channels=" + ",".join(TRACE_REQUIRED_CHANNELS))


@dbg_app.command("health")
def cmd_dbg_health(
    trace_file: Path = typer.Argument(..., help="trace file (.cdt)"),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Summarize CDT telemetry coverage and channel availability."""
    from ..dbg.health import summarize_trace_health
    try:
        summary = summarize_trace_health(
            Path(trace_file),
            tick_start=tick_start,
            tick_end=tick_end,
        )
    except ValueError as exc:
        typer.echo(f"dbg health failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    tick_window = builtin_object_or_empty(summary.get("tick_window"))
    tick_spans_obj = summary.get("tick_spans")
    tick_gaps_obj = summary.get("tick_gaps")
    metrics = builtin_object_or_empty(summary.get("metrics"))
    channels = builtin_object_or_empty(summary.get("channels_present"))
    issues_obj = summary.get("issues")
    issues = [str(item) for item in issues_obj] if isinstance(issues_obj, list) else []
    ok = bool(summary.get("ok_for_parity_analysis"))

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
    typer.echo("tick_spans=" + json.dumps(tick_spans_obj if isinstance(tick_spans_obj, list) else [], sort_keys=True))
    typer.echo("tick_gaps=" + json.dumps(tick_gaps_obj if isinstance(tick_gaps_obj, list) else [], sort_keys=True))
    typer.echo(
        "channels="
        + (",".join(f"{str(key)}:{value}" for key, value in sorted(channels.items())) if channels else "(none)"),
    )
    metric_keys = (
        "ticks_with_dt_ms_i32",
        "validated_tick_records",
        "replay_step_rows",
        "rng_stream_rows",
        "sim_state_rows",
        "sample_creature_rows",
        "sample_projectile_rows",
        "sample_secondary_projectile_rows",
        "sample_bonus_rows",
        "timing_samples_rows",
        "ticks_with_timing_samples",
    )
    for key in metric_keys:
        typer.echo(f"{key}={metrics.get(key)}")
    typer.echo(f"parity_analysis_ready={ok}")
    for issue in issues:
        typer.echo(f"issue={issue}")

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if not bool(ok):
        raise typer.Exit(code=1)


@dbg_app.command("verify")
def cmd_dbg_verify() -> None:
    """Verify dbg schema/replay parity contract wiring."""
    from ..dbg.format_contract import format_contract_errors
    from ..dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION, FRIDA_EVIDENCE_FORMAT_VERSION
    from ..dbg.schema import TRACE_FORMAT_VERSION, TRACE_REQUIRED_CHANNELS, TRACE_SCHEMA_VERSION
    from ..replay.checkpoints import FORMAT_VERSION as CHECKPOINT_FORMAT_VERSION
    from ..replay.types import REPLAY_FORMAT_VERSION

    channels = tuple(str(channel) for channel in TRACE_REQUIRED_CHANNELS)

    typer.echo(f"trace_format_version={int(TRACE_FORMAT_VERSION)}")
    typer.echo(f"trace_schema_version={int(TRACE_SCHEMA_VERSION)}")
    typer.echo(f"replay_format_version={int(REPLAY_FORMAT_VERSION)}")
    typer.echo(f"checkpoint_format_version={int(CHECKPOINT_FORMAT_VERSION)}")
    typer.echo(f"frida_capture_format_version={int(FRIDA_CAPTURE_FORMAT_VERSION)}")
    typer.echo(f"frida_evidence_format_version={int(FRIDA_EVIDENCE_FORMAT_VERSION)}")
    typer.echo("required_channels=" + ",".join(channels))
    errors = format_contract_errors()
    if errors:
        for error in errors:
            typer.echo(f"contract_error={error}", err=True)
        typer.echo("result=failed")
        raise typer.Exit(code=1)
    typer.echo("result=ok")


@dbg_app.command("diff")
def cmd_dbg_diff(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Compare two traces and report the first divergent tick."""
    from ..dbg.diff import diff_report_to_json, diff_traces

    try:
        report = diff_traces(
            expected_trace_path=Path(golden_trace),
            actual_trace_path=Path(candidate_trace),
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
        typer.echo(
            f"result=ok checked={report.checked_count} "
            f"diagnostics={len(report.channel_first_diagnostics)}",
        )
        for channel, first in sorted(report.channel_first_diagnostics.items(), key=lambda item: item[1].tick_index):
            typer.echo(
                f"diagnostic_channel={channel} first_tick={first.tick_index} kind={first.kind}",
            )
        return

    mismatch = report.mismatch
    assert mismatch is not None
    typer.echo(
        f"result=diverged kind={mismatch.kind} tick={mismatch.tick_index} "
        f"checked={report.checked_count} compared={report.compared_count}",
        err=True,
    )
    for channel, first in sorted(report.channel_first_mismatches.items(), key=lambda item: item[1].tick_index):
        path = _first_diff_path(first.detail)
        suffix = "" if path is None else f" path={path}"
        typer.echo(
            f"channel={channel} first_bad_tick={first.tick_index} kind={first.kind}{suffix}",
            err=True,
        )
    for channel, first in sorted(report.channel_first_diagnostics.items(), key=lambda item: item[1].tick_index):
        typer.echo(
            f"diagnostic_channel={channel} first_tick={first.tick_index} kind={first.kind}",
            err=True,
        )
    raise typer.Exit(code=1)


@dbg_app.command("bisect")
def cmd_dbg_bisect(
    golden_trace: Path = typer.Argument(..., help="golden trace (.cdt)"),
    candidate_trace: Path = typer.Argument(..., help="candidate trace (.cdt)"),
    tick_start: int | None = typer.Option(None, "--tick-start", help="optional inclusive lower tick bound"),
    tick_end: int | None = typer.Option(None, "--tick-end", help="optional inclusive upper tick bound"),
    window_before: int = typer.Option(12, "--window-before", min=0, help="ticks before first bad tick in report window"),
    window_after: int = typer.Option(6, "--window-after", min=0, help="ticks after first bad tick in report window"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Bisect divergence and report a compact focus window."""
    from ..dbg.diff import bisect_report_to_json, bisect_traces

    try:
        report = bisect_traces(
            expected_trace_path=Path(golden_trace),
            actual_trace_path=Path(candidate_trace),
            tick_start=tick_start,
            tick_end=tick_end,
            window_before=window_before,
            window_after=window_after,
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
        typer.echo(f"result=ok checked={report.checked_count}")
        return

    mismatch = report.mismatch
    assert mismatch is not None
    typer.echo(
        f"result=diverged first_bad_tick={report.first_bad_tick} "
        f"kind={mismatch.kind} checked={report.checked_count} "
        f"window={report.window_start}..{report.window_end}",
    )
    raise typer.Exit(code=1)


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
    typer.echo(
        "trace_rows "
        + "rng_stream="
        + str(payload.get("rng_stream_count"))
        + " timing_samples="
        + str(payload.get("timing_samples_count")),
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
    json_mode: bool = typer.Option(False, "--json", help="print JSON payload to stdout"),
    json_out: Path | None = typer.Option(None, "--json-out", help="optional JSON output path"),
) -> None:
    """Generate a focused side-by-side report for one tick."""
    from ..dbg.focus import focus_tick

    try:
        payload = focus_tick(
            golden_trace=Path(golden_trace),
            candidate_trace=Path(candidate_trace),
            tick_index=tick,
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
        + " checkpoint_diff_count="
        + str(payload.get("checkpoint_diff_count")),
    )
    rng_stream = _as_dict(payload.get("rng_stream"))
    typer.echo(
        "rng_stream "
        + "prefix_match_len="
        + str(rng_stream.get("behavior_prefix_match_len"))
        + " missing_tail="
        + str(rng_stream.get("missing_tail"))
        + " extra_tail="
        + str(rng_stream.get("extra_tail")),
    )
    entity_samples = _as_dict(payload.get("entity_samples"))
    replay_step = _as_dict(payload.get("replay_step"))
    sim_state = _as_dict(payload.get("sim_state"))
    timing_samples = _as_dict(payload.get("timing_samples"))
    typer.echo(
        "replay_step "
        + "ok="
        + str(replay_step.get("ok")),
    )
    typer.echo(
        "entity_samples "
        + "ok="
        + str(entity_samples.get("ok")),
    )
    typer.echo(
        "sim_state "
        + "ok="
        + str(sim_state.get("ok")),
    )
    typer.echo(
        "timing_samples "
        + "ok="
        + str(timing_samples.get("ok")),
    )
