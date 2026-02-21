from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import typer

original_app = typer.Typer(add_completion=False)
@original_app.command("verify-capture")
def cmd_replay_verify_capture(
    capture_file: Path = typer.Argument(
        ...,
        help="capture file (.json/.json.gz)",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full capture)"),
    seed: int | None = typer.Option(
        None,
        help="seed override for replay reconstruction (default: infer from capture rng telemetry)",
    ),
    strict_events: bool = typer.Option(
        False,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: lenient)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="include presentation RNG draw marks in generated checkpoints",
    ),
    max_field_diffs: int = typer.Option(
        16,
        "--max-field-diffs",
        min=1,
        help="max field-level diffs to print for first mismatching tick",
    ),
    float_abs_tol: float = typer.Option(
        0.001,
        "--float-abs-tol",
        min=0.0,
        help="absolute tolerance for float field comparisons",
    ),
    aim_scheme_player: list[str] = typer.Option(
        [],
        "--aim-scheme-player",
        help=(
            "override replay reconstruction aim scheme as PLAYER=SCHEME (repeatable); "
            "use for captures missing config_aim_scheme telemetry"
        ),
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="optional JSON output path for verify result payload",
    ),
) -> None:
    """Verify capture ticks directly against rewrite simulation state."""
    from ..original.capture import load_capture, parse_player_int_overrides
    from ..original.verify import (
        CaptureVerifyError,
        verify_capture,
    )
    from ..sim.driver.setup import ReplayRunnerError

    capture = load_capture(Path(capture_file))
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    try:
        result, run_result = verify_capture(
            capture,
            seed=seed,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            max_field_diffs=int(max_field_diffs),
            float_abs_tol=float(float_abs_tol),
            aim_scheme_overrides_by_player=aim_scheme_overrides,
        )
    except (ReplayRunnerError, CaptureVerifyError) as exc:
        typer.echo(f"capture verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    def _checkpoint_summary(checkpoint: object | None) -> dict[str, object] | None:
        if checkpoint is None:
            return None
        ckpt = cast("Any", checkpoint)
        return {
            "tick_index": int(ckpt.tick_index),
            "elapsed_ms": int(ckpt.elapsed_ms),
            "score_xp": int(ckpt.score_xp),
            "kills": int(ckpt.kills),
            "creature_count": int(ckpt.creature_count),
            "perk_pending": int(ckpt.perk_pending),
        }

    payload: dict[str, object] = {
        "capture": str(capture_file),
        "ok": bool(result.ok),
        "checked_count": int(result.checked_count),
        "expected_count": int(result.expected_count),
        "actual_count": int(result.actual_count),
        "elapsed_baseline_tick": (
            int(result.elapsed_baseline_tick) if result.elapsed_baseline_tick is not None else None
        ),
        "elapsed_offset_ms": int(result.elapsed_offset_ms) if result.elapsed_offset_ms is not None else None,
        "run_result": {
            "game_mode_id": int(run_result.game_mode_id),
            "tick_rate": int(run_result.tick_rate),
            "ticks": int(run_result.ticks),
            "elapsed_ms": int(run_result.elapsed_ms),
            "score_xp": int(run_result.score_xp),
            "creature_kill_count": int(run_result.creature_kill_count),
            "most_used_weapon_id": int(run_result.most_used_weapon_id),
            "shots_fired": int(run_result.shots_fired),
            "shots_hit": int(run_result.shots_hit),
            "rng_state": int(run_result.rng_state),
        },
        "failure": None,
    }

    if not result.ok:
        failure = result.failure
        assert failure is not None
        payload["failure"] = {
            "kind": str(failure.kind),
            "tick_index": int(failure.tick_index),
            "expected": _checkpoint_summary(failure.expected),
            "actual": _checkpoint_summary(failure.actual),
            "field_diffs": [
                {
                    "field": str(diff.field),
                    "expected": diff.expected,
                    "actual": diff.actual,
                }
                for diff in failure.field_diffs
            ],
        }
        if json_out is not None:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            typer.echo(f"json_report={json_out}")
        typer.echo(f"capture mismatch at tick={int(failure.tick_index)}", err=True)
        typer.echo(
            "  note: compared checkpoint state fields only "
            "(ignoring command_hash/state_hash/rng_state/rng_marks domains)",
            err=True,
        )
        if result.elapsed_baseline_tick is not None and result.elapsed_offset_ms is not None:
            typer.echo(
                "  elapsed baseline "
                f"tick={result.elapsed_baseline_tick} offset_ms(actual-expected)={result.elapsed_offset_ms}",
                err=True,
            )

        if failure.kind == "missing_checkpoint":
            typer.echo("  checkpoint missing in rewrite output", err=True)
            typer.echo(
                f"  checked={result.checked_count}/{result.expected_count} actual_samples={result.actual_count}",
                err=True,
            )
            typer.echo(
                "  run_result "
                f"ticks={run_result.ticks} score_xp={run_result.score_xp} kills={run_result.creature_kill_count}",
                err=True,
            )
            raise typer.Exit(code=1)

        assert failure.actual is not None
        if not failure.field_diffs:
            typer.echo("  mismatch detected but no detailed field diff was collected", err=True)
        else:
            for field_diff in failure.field_diffs:
                typer.echo(
                    f"  {field_diff.field}: expected={field_diff.expected!r} actual={field_diff.actual!r}",
                    err=True,
                )
        typer.echo(
            "  run_result "
            f"ticks={run_result.ticks} score_xp={run_result.score_xp} kills={run_result.creature_kill_count}",
            err=True,
        )
        raise typer.Exit(code=1)

    message = (
        f"ok: {result.checked_count} capture checkpoints match "
        f"(state fields); ticks={run_result.ticks} score_xp={run_result.score_xp} "
        f"kills={run_result.creature_kill_count}"
    )
    if result.elapsed_baseline_tick is not None and result.elapsed_offset_ms is not None:
        message += (
            f"; elapsed baseline tick={result.elapsed_baseline_tick} "
            f"offset_ms(actual-expected)={result.elapsed_offset_ms}"
        )
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")
    typer.echo(message)


@original_app.command("capture-health")
def cmd_original_capture_health(
    capture_file: Path = typer.Argument(
        ...,
        help="capture file (.json/.json.gz)",
    ),
    tick_start: int | None = typer.Option(
        None,
        "--tick-start",
        help="optional inclusive lower tick bound",
    ),
    tick_end: int | None = typer.Option(
        None,
        "--tick-end",
        help="optional inclusive upper tick bound",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="exit non-zero when movement-root-cause telemetry requirements are not met",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="optional JSON output path for telemetry summary",
    ),
) -> None:
    """Summarize capture telemetry coverage before gameplay parity patches."""
    from ..original.capture import load_capture, summarize_capture_health

    capture = load_capture(Path(capture_file))
    try:
        summary = summarize_capture_health(
            capture,
            tick_start=tick_start,
            tick_end=tick_end,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    tick_window_obj = summary.get("tick_window")
    tick_window = cast("dict[str, object]", tick_window_obj) if isinstance(tick_window_obj, dict) else {}
    metrics_obj = summary.get("metrics")
    metrics = cast("dict[str, object]", metrics_obj) if isinstance(metrics_obj, dict) else {}
    issues_obj = summary.get("issues")
    issues = [str(item) for item in issues_obj] if isinstance(issues_obj, list) else []
    ok_for_movement_root_cause = bool(summary.get("ok_for_movement_root_cause"))
    frame_dt_source_after_counts_obj = metrics.get("frame_dt_source_after_counts")
    frame_dt_source_after_counts = (
        cast("dict[str, object]", frame_dt_source_after_counts_obj)
        if isinstance(frame_dt_source_after_counts_obj, dict)
        else {}
    )

    typer.echo(f"capture={capture_file}")
    typer.echo(f"capture_format_version={summary.get('capture_format_version')}")
    typer.echo(
        "tick_window "
        f"requested_start={tick_window.get('requested_start')} "
        f"requested_end={tick_window.get('requested_end')} "
        f"actual_start={tick_window.get('actual_start')} "
        f"actual_end={tick_window.get('actual_end')} "
        f"ticks_total={tick_window.get('ticks_total')} "
        f"ticks_in_window={tick_window.get('ticks_in_window')}",
    )
    metric_keys = (
        "key_rows",
        "key_rows_with_any_signal",
        "perk_apply_in_tick_entries",
        "perk_apply_outside_calls",
        "sample_creature_rows",
        "sample_creature_rows_with_ai_lineage",
        "creature_lifecycle_rows",
        "creature_lifecycle_rows_with_ai_lineage",
        "creature_update_micro_rows",
        "creature_update_micro_angle_rows",
        "creature_update_micro_window_rows",
        "mode_tick_event_count_total",
    )
    for key in metric_keys:
        typer.echo(f"{key}={metrics.get(key)}")
    typer.echo(
        "frame_dt_source_after_counts="
        + (
            ",".join(
                f"{str(key)}:{int(value)}"
                for key, value in sorted(frame_dt_source_after_counts.items(), key=lambda item: str(item[0]))
            )
            if frame_dt_source_after_counts
            else "(none)"
        ),
    )
    typer.echo(f"movement_root_cause_ready={ok_for_movement_root_cause}")
    if issues:
        for issue in issues:
            typer.echo(f"issue={issue}")

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        typer.echo(f"json_report={json_out}")

    if strict and not ok_for_movement_root_cause:
        raise typer.Exit(code=1)


@original_app.command("convert-capture")
def cmd_replay_convert_capture(
    capture_file: Path = typer.Argument(
        ...,
        help="capture file (.json/.json.gz)",
    ),
    output_file: Path = typer.Argument(..., help="output checkpoints sidecar (.crd.chk)"),
    replay_file: Path | None = typer.Option(
        None,
        "--replay",
        help="output replay path (.crd); default: derive from checkpoints path",
    ),
    replay_sha256: str = typer.Option(
        "",
        help="optional replay sha256 to store in the converted sidecar",
    ),
    seed: int | None = typer.Option(
        None,
        help="seed override for replay reconstruction (default: infer from capture rng telemetry)",
    ),
    player_count: int | None = typer.Option(
        None,
        help="player count override for replay reconstruction (default: infer from capture telemetry)",
    ),
    game_mode_id: int | None = typer.Option(
        None,
        help="game mode override for replay reconstruction (default: infer from capture telemetry)",
    ),
    aim_scheme_player: list[str] = typer.Option(
        [],
        "--aim-scheme-player",
        help=(
            "override replay reconstruction aim scheme as PLAYER=SCHEME (repeatable); "
            "use for captures missing config_aim_scheme telemetry"
        ),
    ),
) -> None:
    """Convert capture data into replay + checkpoint artifacts."""
    import hashlib

    from ..original.capture import (
        convert_capture_to_checkpoints,
        convert_capture_to_replay,
        default_capture_replay_path,
        load_capture,
        parse_player_int_overrides,
    )
    from ..replay import dump_replay
    from ..replay.checkpoints import dump_checkpoints_file

    capture = load_capture(Path(capture_file))
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    try:
        replay = convert_capture_to_replay(
            capture,
            seed=seed,
            player_count=player_count,
            game_mode_id=game_mode_id,
            aim_scheme_overrides_by_player=aim_scheme_overrides,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    replay_path = (
        Path(replay_file) if replay_file is not None else default_capture_replay_path(Path(output_file))
    )
    replay_blob = dump_replay(replay)
    replay_path.write_bytes(replay_blob)
    digest = hashlib.sha256(replay_blob).hexdigest()

    checkpoints = convert_capture_to_checkpoints(
        capture,
        replay_sha256=str(replay_sha256 or digest),
    )
    dump_checkpoints_file(Path(output_file), checkpoints)
    typer.echo(f"wrote replay ({len(replay.inputs)} ticks) to {replay_path}")
    typer.echo(f"wrote {len(checkpoints.checkpoints)} checkpoints to {output_file}")
    typer.echo("note: replay uses best-effort input reconstruction; checkpoints remain the authoritative diff target")


def _strip_no_cache_flag(argv: list[str]) -> tuple[list[str], bool]:
    filtered: list[str] = []
    no_cache = False
    for arg in argv:
        if str(arg) == "--no-cache":
            no_cache = True
            continue
        filtered.append(str(arg))
    return filtered, bool(no_cache)


def _run_original_tool_cached(
    *,
    tool: str,
    argv: list[str],
    fallback: Any,
) -> int:
    from ..original import diagnostics_cache, diagnostics_daemon

    args, no_cache = _strip_no_cache_flag(argv)
    if bool(no_cache) or not diagnostics_cache.cache_enabled():
        return int(fallback(args))

    try:
        response = diagnostics_daemon.run_tool_request(
            tool=str(tool),
            args=list(args),
            cwd=Path.cwd(),
        )
        if response.stdout:
            sys.stdout.write(str(response.stdout))
            sys.stdout.flush()
        if response.stderr:
            sys.stderr.write(str(response.stderr))
            sys.stderr.flush()
        return int(response.exit_code)
    except (ConnectionError, OSError, RuntimeError) as exc:
        typer.echo(f"warning: diagnostics cache unavailable ({exc}); falling back to local execution", err=True)
        return int(fallback(args))


@original_app.command(
    "divergence-report",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_divergence_report(ctx: typer.Context) -> None:
    """Run divergence report against a capture."""
    from ..original import divergence_report

    raise typer.Exit(
        code=_run_original_tool_cached(
            tool="divergence-report",
            argv=list(ctx.args),
            fallback=divergence_report.main,
        ),
    )


@original_app.command(
    "bisect-divergence",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_bisect_divergence(ctx: typer.Context) -> None:
    """Binary-search the first divergent tick and emit a compact repro bundle."""
    from ..original import divergence_bisect

    raise typer.Exit(
        code=_run_original_tool_cached(
            tool="bisect-divergence",
            argv=list(ctx.args),
            fallback=divergence_bisect.main,
        ),
    )


@original_app.command(
    "focus-trace",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_focus_trace(ctx: typer.Context) -> None:
    """Trace a single focus tick from capture diagnostics."""
    from ..original import focus_trace

    raise typer.Exit(
        code=_run_original_tool_cached(
            tool="focus-trace",
            argv=list(ctx.args),
            fallback=focus_trace.main,
        ),
    )


@original_app.command(
    "creature-trajectory",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_creature_trajectory(ctx: typer.Context) -> None:
    """Trace capture-vs-rewrite creature trajectory drift."""
    from ..original import creature_trajectory

    raise typer.Exit(code=creature_trajectory.main(list(ctx.args)))


@original_app.command(
    "visualize-capture",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_visualize_capture(ctx: typer.Context) -> None:
    """Visualize capture-vs-rewrite drift with hitbox overlays + movement traces."""
    from ..original import capture_visualizer

    raise typer.Exit(code=capture_visualizer.main(list(ctx.args)))

