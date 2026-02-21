from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import msgspec
import typer
from tqdm import tqdm

from ..game_modes import GameMode
from ..paths import default_runtime_dir

_REPLAY_VERIFY_SCHEMA_VERSION = 1
_REPLAY_BENCHMARK_SCHEMA_VERSION = 1
_REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE = 3


class _ProgressBarLike(Protocol):
    total: int

    def update(self, value: int) -> None: ...

    def set_postfix(self, *, refresh: bool = True, **kwargs: Any) -> None: ...

    def close(self) -> None: ...


def _resolve_replay_path(replay_file: Path, *, base_dir: Path) -> tuple[Path, tuple[Path, ...]]:
    """Resolve a replay path, with a convenience lookup under the runtime dir.

    If the input is just a filename and it doesn't exist in the current directory,
    try `base_dir/replays/<name>`.
    """

    path = Path(replay_file)
    tried: list[Path] = [path]
    if path.is_file():
        return path, tuple(tried)

    if not path.is_absolute() and len(path.parts) == 1:
        under_replays = base_dir / "replays" / path.name
        if under_replays not in tried:
            tried.append(under_replays)
            if under_replays.is_file():
                return under_replays, tuple(tried)

    return path, tuple(tried)


def _default_replay_render_output_path(replay_path: Path) -> Path:
    return Path(replay_path).with_suffix(".render.mp4")


def _replay_render_progress_callback(
    *,
    total_ticks: int,
    render_audio: bool,
    tqdm_factory: Callable[..., object] = tqdm,
) -> tuple[object | None, object | None]:
    if int(total_ticks) <= 0:
        return None, None

    video_bar = cast(
        _ProgressBarLike,
        tqdm_factory(
            total=int(total_ticks),
            unit="tick",
            desc="replay video",
            leave=True,
        ),
    )
    audio_bar: _ProgressBarLike | None = None
    video_last_tick = 0
    audio_last_tick = 0

    def _ensure_audio_bar(total: int) -> _ProgressBarLike:
        nonlocal audio_bar
        if audio_bar is not None:
            return audio_bar
        audio_bar = cast(
            _ProgressBarLike,
            tqdm_factory(
                total=int(total),
                unit="tick",
                desc="replay audio",
                leave=True,
            ),
        )
        return audio_bar

    def callback(phase: str, frame_count: int, tick_index: int, callback_total_ticks: int) -> None:
        nonlocal video_last_tick, audio_last_tick
        resolved_total = int(total_ticks)
        if int(callback_total_ticks) > 0:
            resolved_total = int(callback_total_ticks)
        if int(resolved_total) <= 0:
            return
        if str(phase) == "video":
            bar = video_bar
            last_tick = int(video_last_tick)
        elif str(phase) == "audio":
            if not bool(render_audio):
                return
            bar = _ensure_audio_bar(int(resolved_total))
            last_tick = int(audio_last_tick)
        else:
            return
        if int(bar.total) != int(resolved_total):
            bar.total = int(resolved_total)
        tick = min(int(resolved_total), max(0, int(tick_index)))
        delta = int(tick) - int(last_tick)
        if int(delta) <= 0:
            return
        bar.update(int(delta))
        if str(phase) == "video":
            bar.set_postfix(frames=int(frame_count), refresh=False)
            video_last_tick = int(tick)
        else:
            audio_last_tick = int(tick)

    def close() -> None:
        video_bar.close()
        if audio_bar is not None:
            audio_bar.close()

    return callback, close


def _render_checkpoint_diff_failure(diff: object) -> None:
    diff_obj = cast("Any", diff)
    failure = diff_obj.failure
    assert failure is not None
    exp = failure.expected
    act = failure.actual

    if failure.kind == "missing_checkpoint":
        typer.echo(f"checkpoint missing at tick={int(failure.tick_index)}", err=True)
        raise typer.Exit(code=1)

    if failure.kind == "command_mismatch":
        assert act is not None
        typer.echo(f"checkpoint command mismatch at tick={int(failure.tick_index)}", err=True)
        typer.echo(f"  command_hash expected={exp.command_hash} actual={act.command_hash}", err=True)
        if int(exp.events.hit_count) >= 0:
            typer.echo(
                "  events "
                f"expected=(hits={exp.events.hit_count}, pickups={exp.events.pickup_count}, sfx={exp.events.sfx_count}, head={exp.events.sfx_head}) "
                f"actual=(hits={act.events.hit_count}, pickups={act.events.pickup_count}, sfx={act.events.sfx_count}, head={act.events.sfx_head})",
                err=True,
            )
        raise typer.Exit(code=1)

    assert act is not None
    typer.echo(f"checkpoint mismatch at tick={int(failure.tick_index)}", err=True)
    typer.echo(f"  state_hash expected={exp.state_hash} actual={act.state_hash}", err=True)
    typer.echo(f"  rng_state expected={exp.rng_state} actual={act.rng_state}", err=True)
    typer.echo(f"  score_xp expected={exp.score_xp} actual={act.score_xp}", err=True)
    typer.echo(f"  kills expected={exp.kills} actual={act.kills}", err=True)
    typer.echo(f"  creature_count expected={exp.creature_count} actual={act.creature_count}", err=True)
    typer.echo(f"  perk_pending expected={exp.perk_pending} actual={act.perk_pending}", err=True)
    if failure.first_rng_mark is not None:
        key = str(failure.first_rng_mark)
        typer.echo(
            f"  rng_mark[{key}] expected={exp.rng_marks.get(key)} actual={act.rng_marks.get(key)}",
            err=True,
        )
    typer.echo(f"  deaths expected={len(exp.deaths)} actual={len(act.deaths)}", err=True)
    if exp.deaths or act.deaths:
        typer.echo(f"  first death expected={exp.deaths[:1]} actual={act.deaths[:1]}", err=True)
    if int(exp.events.hit_count) >= 0:
        typer.echo(
            "  events "
            f"expected=(hits={exp.events.hit_count}, pickups={exp.events.pickup_count}, sfx={exp.events.sfx_count}, head={exp.events.sfx_head}) "
            f"actual=(hits={act.events.hit_count}, pickups={act.events.pickup_count}, sfx={act.events.sfx_count}, head={act.events.sfx_head})",
            err=True,
        )
    if exp.perk != act.perk:
        typer.echo(
            "  perk snapshot differs "
            f"(expected pending={exp.perk.pending_count} choices={exp.perk.choices}, "
            f"actual pending={act.perk.pending_count} choices={act.perk.choices})",
            err=True,
        )
    raise typer.Exit(code=1)


def _resolve_replay_verify_metric(
    *,
    game_mode_id: int,
    score_metric: Literal["auto", "score_xp", "elapsed_ms"],
) -> Literal["score_xp", "elapsed_ms"]:
    if str(score_metric) == "score_xp":
        return "score_xp"
    if str(score_metric) == "elapsed_ms":
        return "elapsed_ms"
    if int(game_mode_id) in (int(GameMode.RUSH), int(GameMode.QUESTS)):
        return "elapsed_ms"
    return "score_xp"


class _RunResultPayload(msgspec.Struct, forbid_unknown_fields=True):
    game_mode_id: int
    tick_rate: int
    ticks: int
    elapsed_ms: int
    score_xp: int
    creature_kill_count: int
    most_used_weapon_id: int
    shots_fired: int
    shots_hit: int
    rng_state: int


class _ReplayVerifyScoreClaimPayload(msgspec.Struct, forbid_unknown_fields=True):
    metric: str
    submitted_score: int
    simulated_value: int
    match: bool


class _ReplayVerifyPayload(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    status: str
    replay: str
    replay_sha256: str
    run_result: _RunResultPayload
    score_claim: _ReplayVerifyScoreClaimPayload | None


class _BenchmarkAggregatePayload(msgspec.Struct, forbid_unknown_fields=True):
    min: float
    p50: float
    mean: float
    p95: float
    max: float
    stdev: float


class _ReplayBenchmarkProfileHotspotPayload(msgspec.Struct, forbid_unknown_fields=True):
    file: str
    line: int
    function: str
    primitive_calls: int
    total_calls: int
    tottime: float
    cumtime: float


class _ReplayBenchmarkProfilePayload(msgspec.Struct, forbid_unknown_fields=True):
    sort: str
    top: int
    source: str
    hotspots: list[_ReplayBenchmarkProfileHotspotPayload]


class _ReplayBenchmarkSettingsPayload(msgspec.Struct, forbid_unknown_fields=True):
    mode: str
    runs: int
    warmup_runs: int
    max_ticks: int | None
    strict_events: bool
    trace_rng: bool
    profile: bool
    profile_sort: str
    top: int
    profile_out: str | None


class _ReplayBenchmarkSamplePayload(msgspec.Struct, forbid_unknown_fields=True):
    wall_ms: float
    ticks_per_second: float
    realtime_x: float


class _ReplayBenchmarkSummaryPayload(msgspec.Struct, forbid_unknown_fields=True):
    sample_count: int
    samples: list[_ReplayBenchmarkSamplePayload]
    wall_ms: _BenchmarkAggregatePayload
    ticks_per_second: _BenchmarkAggregatePayload
    realtime_x: _BenchmarkAggregatePayload


class _ReplayBenchmarkPayload(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    status: str
    replay: str
    replay_sha256: str
    settings: _ReplayBenchmarkSettingsPayload
    run_result: _RunResultPayload
    benchmark: _ReplayBenchmarkSummaryPayload
    profile: _ReplayBenchmarkProfilePayload | None


def _run_result_payload(run_result: object) -> _RunResultPayload:
    result = cast("Any", run_result)
    return _RunResultPayload(
        game_mode_id=int(result.game_mode_id),
        tick_rate=int(result.tick_rate),
        ticks=int(result.ticks),
        elapsed_ms=int(result.elapsed_ms),
        score_xp=int(result.score_xp),
        creature_kill_count=int(result.creature_kill_count),
        most_used_weapon_id=int(result.most_used_weapon_id),
        shots_fired=int(result.shots_fired),
        shots_hit=int(result.shots_hit),
        rng_state=int(result.rng_state),
    )


def _benchmark_aggregate_payload(aggregate: object) -> _BenchmarkAggregatePayload:
    entry = cast("Any", aggregate)
    return _BenchmarkAggregatePayload(
        min=float(entry.min),
        p50=float(entry.p50),
        mean=float(entry.mean),
        p95=float(entry.p95),
        max=float(entry.max),
        stdev=float(entry.stdev),
    )


def _fmt_metric_agg(name: str, aggregate: object, *, digits: int) -> str:
    entry = cast("Any", aggregate)
    return (
        f"{name} "
        f"min={float(entry.min):.{digits}f} "
        f"p50={float(entry.p50):.{digits}f} "
        f"mean={float(entry.mean):.{digits}f} "
        f"p95={float(entry.p95):.{digits}f} "
        f"max={float(entry.max):.{digits}f} "
        f"stdev={float(entry.stdev):.{digits}f}"
    )


replay_app = typer.Typer(add_completion=False)
@replay_app.command("play")
def cmd_replay_play(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
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
    """Play back a recorded replay."""
    from grim.app import RunViewHooks, run_view
    from grim.config import ensure_crimson_cfg
    from grim.console import create_console
    from grim.view import ViewContext

    from ..assets_fetch import download_missing_paqs
    from ..modes.replay_playback_mode import ReplayPlaybackMode

    if assets_dir is None:
        assets_dir = base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)
    cfg = ensure_crimson_cfg(base_dir)
    if width is None:
        width = cfg.screen_width
    if height is None:
        height = cfg.screen_height
    console = create_console(base_dir, assets_dir=assets_dir)
    download_missing_paqs(assets_dir, console)

    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=False)
    view = ReplayPlaybackMode(ctx, replay_path=replay_path, config=cfg, console=console)
    title = f"Replay — {replay_path.name}"
    run_view(
        view,
        width=width,
        height=height,
        title=title,
        fps=fps,
        hooks=RunViewHooks(
            should_close=view.should_close,
            consume_screenshot_request=view.consume_screenshot_request,
        ),
    )


@replay_app.command("list")
def cmd_replay_list(
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """List replay files under base-dir/replays."""
    replays_dir = Path(base_dir) / "replays"
    replay_files = sorted(
        (path for path in replays_dir.rglob("*.crd") if path.is_file()),
        key=lambda path: str(path.relative_to(replays_dir)),
    )
    if not replay_files:
        typer.echo(f"no replay files found under {replays_dir}")
        return
    for replay_path in replay_files:
        rel = replay_path.relative_to(replays_dir)
        typer.echo(str(rel))
    typer.echo(f"count={len(replay_files)}")


@replay_app.command("verify")
def cmd_replay_verify(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    strict_events: bool = typer.Option(
        True,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: strict)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="enable replay RNG trace mode during simulation",
    ),
    output_format: Literal["human", "json"] = typer.Option(
        "human",
        "--format",
        help="output format",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="optional JSON output path for verify result payload",
    ),
    submitted_score: int | None = typer.Option(
        None,
        "--submitted-score",
        help="optional submitted score/time to compare against simulated result",
    ),
    score_metric: Literal["auto", "score_xp", "elapsed_ms"] = typer.Option(
        "auto",
        "--score-metric",
        help="score metric for submitted score validation",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Headlessly simulate a replay and report resulting run stats."""
    import hashlib

    from ..replay import ReplayCodecError, load_replay
    from ..sim.driver.replay_runner import ReplayRunnerError, run_replay

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    replay_sha256 = hashlib.sha256(replay_bytes).hexdigest()
    try:
        replay = load_replay(replay_bytes)
        result = run_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
        )
    except (ReplayCodecError, ReplayRunnerError) as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    resolved_metric = _resolve_replay_verify_metric(
        game_mode_id=int(result.game_mode_id),
        score_metric=score_metric,
    )
    score_claim_payload: _ReplayVerifyScoreClaimPayload | None = None
    status = "ok"
    claim_matches = True
    if submitted_score is not None:
        simulated_value = int(result.score_xp) if resolved_metric == "score_xp" else int(result.elapsed_ms)
        claim_matches = int(submitted_score) == int(simulated_value)
        if not claim_matches:
            status = "score_mismatch"
        score_claim_payload = _ReplayVerifyScoreClaimPayload(
            metric=str(resolved_metric),
            submitted_score=int(submitted_score),
            simulated_value=int(simulated_value),
            match=bool(claim_matches),
        )

    payload = _ReplayVerifyPayload(
        schema_version=int(_REPLAY_VERIFY_SCHEMA_VERSION),
        status=str(status),
        replay=str(replay_path),
        replay_sha256=str(replay_sha256),
        run_result=_run_result_payload(result),
        score_claim=score_claim_payload,
    )
    payload_json = msgspec.json.encode(payload)

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)
        if str(output_format) == "human":
            typer.echo(f"json_report={json_out}")

    if str(output_format) == "json":
        typer.echo(payload_json.decode("utf-8"))
    else:
        message = (
            f"{'ok' if status == 'ok' else 'score_mismatch'}: "
            f"ticks={result.ticks} elapsed_ms={result.elapsed_ms} score_xp={result.score_xp} "
            f"kills={result.creature_kill_count} most_used_weapon_id={result.most_used_weapon_id} "
            f"shots_fired={result.shots_fired} shots_hit={result.shots_hit} rng_state={result.rng_state}"
        )
        if score_claim_payload is not None:
            message += (
                f"; score_claim metric={score_claim_payload.metric} "
                f"submitted={score_claim_payload.submitted_score} "
                f"simulated={score_claim_payload.simulated_value} "
                f"match={score_claim_payload.match}"
            )
        typer.echo(message)

    if not claim_matches:
        raise typer.Exit(code=int(_REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE))


@replay_app.command("benchmark")
def cmd_replay_benchmark(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    runs: int = typer.Option(5, "--runs", min=1, help="number of measured benchmark runs"),
    warmup_runs: int = typer.Option(1, "--warmup-runs", min=0, help="warmup runs before measured timing"),
    mode: Literal["headless", "render"] = typer.Option(
        "headless",
        "--mode",
        help="benchmark mode: headless|render",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    strict_events: bool = typer.Option(
        True,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: strict)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="enable replay RNG trace mode during simulation",
    ),
    profile: bool = typer.Option(False, "--profile", help="run one cProfile pass and include hotspot summary"),
    profile_sort: Literal["cumtime", "tottime"] = typer.Option(
        "cumtime",
        "--profile-sort",
        help="hotspot sort key",
    ),
    top: int = typer.Option(20, "--top", min=1, help="maximum hotspot rows to include"),
    profile_out: Path | None = typer.Option(
        None,
        "--profile-out",
        help="optional cProfile .pstats output path (used only with --profile)",
    ),
    output_format: Literal["human", "json"] = typer.Option(
        "human",
        "--format",
        help="output format",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="optional JSON output path for benchmark payload",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Benchmark replay throughput, with optional profiler hotspots."""
    import hashlib

    from ..replay import ReplayCodecError, load_replay
    from ..sim.driver.replay_benchmark import (
        ReplayBenchmarkError,
        run_replay_benchmark,
        run_replay_render_benchmark,
    )
    from ..sim.driver.replay_runner import ReplayRunnerError

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    replay_sha256 = hashlib.sha256(replay_bytes).hexdigest()

    try:
        replay = load_replay(replay_bytes)
        if str(mode) == "render":
            benchmark = run_replay_render_benchmark(
                replay,
                replay_path=Path(replay_path),
                base_dir=Path(base_dir),
                runs=int(runs),
                warmup_runs=int(warmup_runs),
                max_ticks=max_ticks,
                strict_events=bool(strict_events),
                trace_rng=bool(trace_rng),
                profile=bool(profile),
                profile_sort=profile_sort,
                top=int(top),
                profile_out=profile_out,
            )
        else:
            benchmark = run_replay_benchmark(
                replay,
                runs=int(runs),
                warmup_runs=int(warmup_runs),
                max_ticks=max_ticks,
                strict_events=bool(strict_events),
                trace_rng=bool(trace_rng),
                profile=bool(profile),
                profile_sort=profile_sort,
                top=int(top),
                profile_out=profile_out,
            )
    except (ReplayCodecError, ReplayBenchmarkError, ReplayRunnerError) as exc:
        typer.echo(f"replay benchmark failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    profile_payload: _ReplayBenchmarkProfilePayload | None = None
    if benchmark.profile is not None:
        profile_payload = _ReplayBenchmarkProfilePayload(
            sort=str(benchmark.profile.sort),
            top=int(benchmark.profile.top),
            source=str(benchmark.profile.source),
            hotspots=[
                _ReplayBenchmarkProfileHotspotPayload(
                    file=str(row.file),
                    line=int(row.line),
                    function=str(row.function),
                    primitive_calls=int(row.primitive_calls),
                    total_calls=int(row.total_calls),
                    tottime=float(row.tottime),
                    cumtime=float(row.cumtime),
                )
                for row in benchmark.profile.hotspots
            ],
        )

    payload = _ReplayBenchmarkPayload(
        schema_version=int(_REPLAY_BENCHMARK_SCHEMA_VERSION),
        status="ok",
        replay=str(replay_path),
        replay_sha256=str(replay_sha256),
        settings=_ReplayBenchmarkSettingsPayload(
            mode=str(mode),
            runs=int(runs),
            warmup_runs=int(warmup_runs),
            max_ticks=(int(max_ticks) if max_ticks is not None else None),
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            profile=bool(profile),
            profile_sort=str(profile_sort),
            top=int(top),
            profile_out=(str(profile_out) if profile_out is not None else None),
        ),
        run_result=_run_result_payload(benchmark.run_result),
        benchmark=_ReplayBenchmarkSummaryPayload(
            sample_count=int(len(benchmark.samples)),
            samples=[
                _ReplayBenchmarkSamplePayload(
                    wall_ms=float(sample.wall_ms),
                    ticks_per_second=float(sample.ticks_per_second),
                    realtime_x=float(sample.realtime_x),
                )
                for sample in benchmark.samples
            ],
            wall_ms=_benchmark_aggregate_payload(benchmark.wall_ms),
            ticks_per_second=_benchmark_aggregate_payload(benchmark.ticks_per_second),
            realtime_x=_benchmark_aggregate_payload(benchmark.realtime_x),
        ),
        profile=profile_payload,
    )
    payload_json = msgspec.json.encode(payload)

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)
        if str(output_format) == "human":
            typer.echo(f"json_report={json_out}")

    if str(output_format) == "json":
        typer.echo(payload_json.decode("utf-8"))
        return

    typer.echo(
        "ok: "
        f"mode={mode} "
        f"runs={len(benchmark.samples)} warmup_runs={int(warmup_runs)} "
        f"ticks={int(benchmark.run_result.ticks)} "
        f"wall_ms_p50={float(benchmark.wall_ms.p50):.3f} "
        f"tps_p50={float(benchmark.ticks_per_second.p50):.2f} "
        f"realtime_x_p50={float(benchmark.realtime_x.p50):.2f}",
    )
    typer.echo(_fmt_metric_agg("wall_ms", benchmark.wall_ms, digits=3))
    typer.echo(
        _fmt_metric_agg("throughput_tps", benchmark.ticks_per_second, digits=2)
        + " | "
        + _fmt_metric_agg("realtime_x", benchmark.realtime_x, digits=2),
    )
    if benchmark.profile is None:
        return
    typer.echo(
        f"profile: sort={benchmark.profile.sort} source={benchmark.profile.source} "
        f"top={benchmark.profile.top}",
    )
    typer.echo("hotspots:")
    if not benchmark.profile.hotspots:
        typer.echo("  (none)")
        return
    for idx, row in enumerate(benchmark.profile.hotspots, start=1):
        typer.echo(
            f"  {idx:02d} cum={float(row.cumtime):.6f}s tot={float(row.tottime):.6f}s "
            f"calls={int(row.primitive_calls)}/{int(row.total_calls)} "
            f"{row.file}:{int(row.line)}::{row.function}",
        )


@replay_app.command("render")
def cmd_replay_render(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="output video path (default: <replay>.render.mp4)",
    ),
    width: int | None = typer.Option(None, help="render width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="render height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, "--fps", min=1, help="output video fps"),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    strict_events: bool = typer.Option(
        True,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: strict)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="enable replay RNG trace mode during simulation",
    ),
    ffmpeg_bin: Path | None = typer.Option(
        None,
        "--ffmpeg-bin",
        help="ffmpeg executable path (default: discover from PATH)",
    ),
    crf: int = typer.Option(
        16,
        "--crf",
        min=0,
        max=51,
        help="ffmpeg quality factor (libx264: lower is higher quality)",
    ),
    preset: Literal[
        "ultrafast",
        "superfast",
        "veryfast",
        "faster",
        "fast",
        "medium",
        "slow",
        "slower",
        "veryslow",
    ] = typer.Option("slow", "--preset", help="ffmpeg libx264 preset"),
    pixel_format: str = typer.Option(
        "yuv420p",
        "--pixel-format",
        help="ffmpeg output pixel format",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="overwrite output if it already exists",
    ),
    audio: bool = typer.Option(
        True,
        "--audio/--mute-audio",
        help="include in-game audio in output video",
    ),
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
    """Render replay playback to video using ffmpeg."""
    from ..replay import ReplayCodecError, load_replay
    from ..sim.driver.replay_render import ReplayRenderError, run_replay_render_video
    from ..sim.driver.replay_runner import ReplayRunnerError

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    output_path = Path(out) if out is not None else _default_replay_render_output_path(replay_path)

    replay_bytes = Path(replay_path).read_bytes()
    progress_close: object | None = None
    try:
        replay = load_replay(replay_bytes)
        total_ticks = int(len(replay.inputs))
        if max_ticks is not None:
            total_ticks = min(int(total_ticks), max(0, int(max_ticks)))
        progress_callback, progress_close = _replay_render_progress_callback(
            total_ticks=total_ticks,
            render_audio=bool(audio),
        )
        render = run_replay_render_video(
            replay,
            replay_path=Path(replay_path),
            output_path=Path(output_path),
            base_dir=Path(base_dir),
            assets_dir=(Path(assets_dir) if assets_dir is not None else None),
            width=width,
            height=height,
            fps=int(fps),
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            ffmpeg_bin=(Path(ffmpeg_bin) if ffmpeg_bin is not None else None),
            crf=int(crf),
            preset=preset,
            pixel_format=str(pixel_format),
            overwrite=bool(overwrite),
            mute_audio=not bool(audio),
            progress=cast("Any", progress_callback),
        )
    except (ReplayCodecError, ReplayRenderError, ReplayRunnerError) as exc:
        typer.echo(f"replay render failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if progress_close is not None:
            cast("Any", progress_close)()

    message = (
        f"ok: output={render.output_path} "
        f"frames={render.frame_count} fps={render.fps} "
        f"resolution={render.width}x{render.height} "
        f"ticks={render.run_result.ticks} elapsed_ms={render.run_result.elapsed_ms} "
        f"score_xp={render.run_result.score_xp} kills={render.run_result.creature_kill_count}"
    )
    typer.echo(message)


@replay_app.command("verify-checkpoints")
def cmd_replay_verify_checkpoints(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    checkpoints_file: Path | None = typer.Option(
        None,
        "--checkpoints",
        help="checkpoint sidecar path (default: <replay>.chk)",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    strict_events: bool = typer.Option(
        True,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: strict)",
    ),
    strict_integrity: bool = typer.Option(
        True,
        "--strict-integrity/--lenient-integrity",
        help="fail if checkpoints replay_sha256 differs from replay file (default: strict)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="include presentation RNG draw marks in verification checkpoints",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Verify a replay by comparing headless checkpoints with a sidecar file."""
    import hashlib

    from ..original.diff import compare_checkpoints
    from ..replay import ReplayCodecError, load_replay
    from ..replay.checkpoints import (
        ReplayCheckpointsError,
        default_checkpoints_path,
        legacy_checkpoints_path,
        load_checkpoints_file,
    )
    from ..sim.driver.replay_runner import ReplayRunnerError, run_replay

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    replay_sha256 = hashlib.sha256(replay_bytes).hexdigest()
    try:
        replay = load_replay(replay_bytes)
    except ReplayCodecError as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if checkpoints_file is None:
        checkpoints_path = default_checkpoints_path(replay_path)
        if not checkpoints_path.is_file():
            legacy_path = legacy_checkpoints_path(replay_path)
            if legacy_path.is_file():
                checkpoints_path = legacy_path
    else:
        checkpoints_path = Path(checkpoints_file)
    if not checkpoints_path.is_file():
        typer.echo(f"checkpoints file not found: {checkpoints_path}", err=True)
        raise typer.Exit(code=1)

    try:
        expected = load_checkpoints_file(checkpoints_path)
    except ReplayCheckpointsError as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if expected.replay_sha256 and str(expected.replay_sha256) != str(replay_sha256):
        mismatch = (
            "checkpoints replay_sha256 mismatch "
            f"(checkpoints={expected.replay_sha256!r}, replay={replay_sha256!r})"
        )
        if strict_integrity:
            typer.echo(f"replay verification failed: {mismatch}", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"warning: {mismatch}", err=True)

    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected.checkpoints}
    actual = []

    try:
        result = run_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
            checkpoints_out=actual,
            checkpoint_ticks=checkpoint_ticks,
        )
    except ReplayRunnerError as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    diff = compare_checkpoints(expected.checkpoints, actual)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = (
        f"ok: {len(expected.checkpoints)} checkpoints match; ticks={result.ticks} "
        f"score_xp={result.score_xp} kills={result.creature_kill_count}"
    )
    if diff.first_rng_only_tick is not None:
        message += f"; rng-only drift starts at tick={diff.first_rng_only_tick}"
    typer.echo(message)


@replay_app.command("diff-checkpoints")
def cmd_replay_diff_checkpoints(
    expected_file: Path = typer.Argument(..., help="expected checkpoints sidecar (.crd.chk)"),
    actual_file: Path = typer.Argument(..., help="actual checkpoints sidecar (.crd.chk)"),
) -> None:
    """Compare two checkpoint sidecars and report the first divergence."""
    from ..original.diff import compare_checkpoints
    from ..replay.checkpoints import load_checkpoints_file

    expected = load_checkpoints_file(Path(expected_file))
    actual = load_checkpoints_file(Path(actual_file))
    diff = compare_checkpoints(expected.checkpoints, actual.checkpoints)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = f"ok: {len(expected.checkpoints)} checkpoints match"
    if diff.first_rng_only_tick is not None:
        message += f"; rng-only drift starts at tick={diff.first_rng_only_tick}"
    typer.echo(message)
