from __future__ import annotations

import cProfile
import json
import math
import pstats
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast

import msgspec
from tqdm import tqdm

from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.raylib_api import rl
from grim.view import ViewContext

from ...modes.replay_playback_mode import ReplayPlaybackMode
from ...replay import Replay
from ...sim.run_result import RunResult, run_result_mismatches
from .playback_driver import PlaybackWalkObserver, build_verify_playback_driver
from .render_telemetry import RenderTelemetryFrame, RenderTelemetrySession
from .render_telemetry_charts import write_render_telemetry_charts

ProfileSortKey = Literal["cumtime", "tottime"]
HotspotSource = Literal["project", "all"]


class _TickBar(PlaybackWalkObserver):
    """Advances a tqdm tick bar as the playback walk reaches each tick."""

    bar: tqdm

    def progress(self, next_tick_index: int) -> None:
        self.bar.update(next_tick_index - self.bar.n)


def _step_done(run_bar: tqdm, postfix: str) -> None:
    run_bar.set_postfix_str(postfix, refresh=False)
    run_bar.update(1)


def _path_text(path: Path | None) -> str | None:
    return None if path is None else str(path)


class ReplayBenchmarkError(ValueError):
    pass


class BenchmarkSample(msgspec.Struct, frozen=True):
    wall_ms: float
    ticks_per_second: float
    realtime_x: float


class BenchmarkAggregate(msgspec.Struct, frozen=True):
    min: float
    p50: float
    mean: float
    p95: float
    max: float
    stdev: float


class ReplayProfileHotspot(msgspec.Struct, frozen=True):
    file: str
    line: int
    function: str
    primitive_calls: int
    total_calls: int
    tottime: float
    cumtime: float


class ReplayProfileResult(msgspec.Struct, frozen=True):
    sort: ProfileSortKey
    top: int
    source: HotspotSource
    hotspots: tuple[ReplayProfileHotspot, ...]


class ReplayRenderTelemetryTopTick(msgspec.Struct, frozen=True):
    tick_index: int
    frame_index: int
    value: float


class ReplayRenderTelemetrySummary(msgspec.Struct, frozen=True):
    frame_ms: BenchmarkAggregate
    update_ms: BenchmarkAggregate
    draw_ms: BenchmarkAggregate
    draw_calls_total: BenchmarkAggregate
    top_draw_ms_ticks: tuple[ReplayRenderTelemetryTopTick, ...]
    top_frame_ms_ticks: tuple[ReplayRenderTelemetryTopTick, ...]
    top_draw_calls_ticks: tuple[ReplayRenderTelemetryTopTick, ...]


class ReplayRenderTelemetryArtifacts(msgspec.Struct, frozen=True):
    telemetry_json_path: str | None = None
    charts_dir: str | None = None
    frame_timing_svg: str | None = None
    draw_calls_svg: str | None = None
    pass_timing_stacked_svg: str | None = None
    report_md: str | None = None


class ReplayRenderTelemetryResult(msgspec.Struct, frozen=True):
    frames: tuple[RenderTelemetryFrame, ...]
    summary: ReplayRenderTelemetrySummary
    artifacts: ReplayRenderTelemetryArtifacts | None = None
    preview: tuple[RenderTelemetryFrame, ...] = ()


class ReplayBenchmarkResult(msgspec.Struct, frozen=True):
    ticks: int
    run_result: RunResult
    samples: tuple[BenchmarkSample, ...]
    wall_ms: BenchmarkAggregate
    ticks_per_second: BenchmarkAggregate
    realtime_x: BenchmarkAggregate
    profile: ReplayProfileResult | None
    render_telemetry: ReplayRenderTelemetryResult | None = None


class _RenderOnceResult(msgspec.Struct, frozen=True):
    run_result: RunResult
    telemetry_frames: tuple[RenderTelemetryFrame, ...] = ()


def run_replay_render_benchmark(
    replay: Replay,
    *,
    replay_path: Path,
    base_dir: Path,
    assets_dir: Path | None = None,
    width: int | None = None,
    height: int | None = None,
    runs: int = 5,
    warmup_runs: int = 1,
    max_ticks: int | None = None,
    profile: bool = False,
    profile_sort: ProfileSortKey = "cumtime",
    top: int = 20,
    profile_out: Path | None = None,
    mute_audio: bool = True,
    render_telemetry: bool = False,
    render_telemetry_out: Path | None = None,
    render_charts_out_dir: Path | None = None,
    rtx: bool = False,
    show_progress: bool = False,
) -> ReplayBenchmarkResult:
    from grim.assets import load_runtime_resources, unload_runtime_resources
    from grim.raylib_api import rl

    from ...runtime_boot import boot_runtime

    _validate_args(runs=runs, warmup_runs=warmup_runs, top=top)
    telemetry_requested = bool(
        render_telemetry
        or render_telemetry_out is not None
        or render_charts_out_dir is not None,
    )

    baseline_result = build_verify_playback_driver(replay, max_ticks=max_ticks).run()

    runtime_assets_dir = Path(assets_dir) if assets_dir is not None else Path(base_dir)
    boot = boot_runtime(Path(base_dir), runtime_assets_dir, width=width, height=height)
    cfg = boot.config
    console = boot.console
    render_width = boot.width
    render_height = boot.height
    if render_width <= 0 or render_height <= 0:
        raise ReplayBenchmarkError(
            f"invalid render resolution: {render_width}x{render_height}; width/height must be > 0",
        )
    if bool(mute_audio):
        cfg.audio.sound_disabled = True
        cfg.audio.music_disabled = True

    ctx = ViewContext(assets_dir=runtime_assets_dir, preserve_bugs=False)

    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_HIDDEN | rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)
    resources = None
    window_open = False
    try:
        rl.init_window(int(render_width), int(render_height), f"Replay Benchmark - {Path(replay_path).name}")
        window_open = True
    except RuntimeError as exc:
        raise ReplayBenchmarkError(f"render benchmark could not initialize window: {exc}") from exc

    tick_total = _tick_total(replay, max_ticks)
    planned_steps = int(warmup_runs) + int(runs) + (1 if bool(profile) else 0) + (1 if telemetry_requested else 0)
    run_bar = tqdm(total=planned_steps, unit="run", desc="render benchmark", leave=False, disable=not show_progress)
    try:
        resources = load_runtime_resources(runtime_assets_dir)

        def _run_once(tick_desc: str, telemetry_session: RenderTelemetrySession | None = None) -> _RenderOnceResult:
            with tqdm(total=tick_total, unit="tick", desc=tick_desc, leave=False, disable=not show_progress) as bar:
                return _run_render_once(
                    ctx=ctx,
                    replay=replay,
                    cfg=cfg,
                    console=console,
                    max_ticks=max_ticks,
                    rtx=bool(rtx),
                    telemetry_session=telemetry_session,
                    observer=_TickBar(bar=bar),
                )

        measured = _measure_runs(
            lambda tick_desc: _run_once(tick_desc).run_result,
            mode="render",
            baseline=baseline_result,
            tick_total=tick_total,
            runs=runs,
            warmup_runs=warmup_runs,
            profile=profile,
            profile_sort=profile_sort,
            top=top,
            profile_out=profile_out,
            run_bar=run_bar,
        )

        telemetry_result: ReplayRenderTelemetryResult | None = None
        if telemetry_requested:
            telemetry_session = RenderTelemetrySession()
            with telemetry_session:
                collected = _run_once("render ticks telemetry", telemetry_session)
            _assert_consistent_run_result(
                baseline_result,
                collected.run_result,
                where="render telemetry run",
            )

            frames = collected.telemetry_frames
            summary = _summarize_render_telemetry(frames=frames)

            telemetry_json_path: Path | None = None
            if render_telemetry_out is not None:
                telemetry_json_path = Path(render_telemetry_out)
                telemetry_json_path.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "frames": [msgspec.to_builtins(frame) for frame in frames],
                    "summary": msgspec.to_builtins(summary),
                }
                telemetry_json_path.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

            chart_paths: dict[str, Path] = {}
            if render_charts_out_dir is not None:
                chart_paths = write_render_telemetry_charts(
                    frames=list(frames),
                    out_dir=Path(render_charts_out_dir),
                    telemetry_json_path=telemetry_json_path,
                )

            artifacts = ReplayRenderTelemetryArtifacts(
                telemetry_json_path=_path_text(telemetry_json_path),
                charts_dir=_path_text(render_charts_out_dir),
                frame_timing_svg=_path_text(chart_paths.get("frame_timing_svg")),
                draw_calls_svg=_path_text(chart_paths.get("draw_calls_svg")),
                pass_timing_stacked_svg=_path_text(chart_paths.get("pass_timing_stacked_svg")),
                report_md=_path_text(chart_paths.get("report_md")),
            )
            telemetry_result = ReplayRenderTelemetryResult(
                frames=frames,
                summary=summary,
                artifacts=artifacts,
                preview=tuple(frames[:10]),
            )
            _step_done(run_bar, "phase=telemetry")
    finally:
        run_bar.close()
        unload_runtime_resources(resources)
        if window_open:
            rl.close_window()

    return _benchmark_result(tick_total, measured, render_telemetry=telemetry_result)


def run_replay_benchmark(
    replay: Replay,
    *,
    runs: int = 5,
    warmup_runs: int = 1,
    max_ticks: int | None = None,
    profile: bool = False,
    profile_sort: ProfileSortKey = "cumtime",
    top: int = 20,
    profile_out: Path | None = None,
    show_progress: bool = False,
) -> ReplayBenchmarkResult:
    _validate_args(runs=runs, warmup_runs=warmup_runs, top=top)

    tick_total = _tick_total(replay, max_ticks)
    planned_steps = int(warmup_runs) + int(runs) + (1 if bool(profile) else 0)
    run_bar = tqdm(total=planned_steps, unit="run", desc="headless benchmark", leave=False, disable=not show_progress)
    try:

        def _run_once(tick_desc: str) -> RunResult:
            with tqdm(total=tick_total, unit="tick", desc=tick_desc, leave=False, disable=not show_progress) as bar:
                driver = build_verify_playback_driver(replay, max_ticks=max_ticks)
                return driver.run(observer=_TickBar(bar=bar))

        measured = _measure_runs(
            _run_once,
            mode="headless",
            baseline=None,
            tick_total=tick_total,
            runs=runs,
            warmup_runs=warmup_runs,
            profile=profile,
            profile_sort=profile_sort,
            top=top,
            profile_out=profile_out,
            run_bar=run_bar,
        )
    finally:
        run_bar.close()

    return _benchmark_result(tick_total, measured)


def _tick_total(replay: Replay, max_ticks: int | None) -> int:
    if max_ticks is None:
        return len(replay.ticks)
    return min(len(replay.ticks), max(0, int(max_ticks)))


class _MeasuredRuns(msgspec.Struct, frozen=True):
    run_result: RunResult
    samples: tuple[BenchmarkSample, ...]
    profile: ReplayProfileResult | None


def _measure_runs(
    run_once: Callable[[str], RunResult],
    *,
    mode: str,
    baseline: RunResult | None,
    tick_total: int,
    runs: int,
    warmup_runs: int,
    profile: bool,
    profile_sort: ProfileSortKey,
    top: int,
    profile_out: Path | None,
    run_bar: tqdm,
) -> _MeasuredRuns:
    """Warmup, timed and profiled runs; each must reproduce `baseline`, or the first timed run without one."""
    for _ in range(int(warmup_runs)):
        run_once(f"{mode} ticks warmup")
        _step_done(run_bar, "phase=warmup")

    samples: list[BenchmarkSample] = []
    for sample_idx in range(int(runs)):
        start_ns = time.perf_counter_ns()
        result = run_once(f"{mode} ticks sample {sample_idx + 1}/{int(runs)}")
        elapsed_ns = max(1, int(time.perf_counter_ns()) - int(start_ns))
        wall_ms = float(elapsed_ns) / 1_000_000.0
        wall_s = float(elapsed_ns) / 1_000_000_000.0
        samples.append(
            BenchmarkSample(
                wall_ms=float(wall_ms),
                ticks_per_second=float(tick_total) / wall_s,
                realtime_x=float(result.elapsed_ms) / wall_ms,
            ),
        )
        if baseline is None:
            baseline = result
        else:
            _assert_consistent_run_result(baseline, result, where=f"{mode} run {sample_idx + 1}")
        _step_done(run_bar, f"phase=measure sample={sample_idx + 1}/{int(runs)}")
    assert baseline is not None

    profile_result: ReplayProfileResult | None = None
    if bool(profile):
        prof = cProfile.Profile()
        prof.enable()
        profiled = run_once(f"{mode} ticks profile")
        prof.disable()
        _assert_consistent_run_result(baseline, profiled, where=f"{mode} profiled run")

        if profile_out is not None:
            out_path = Path(profile_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            prof.dump_stats(str(out_path))

        source, hotspots = _extract_hotspots(prof, sort_key=profile_sort, top=int(top))
        profile_result = ReplayProfileResult(
            sort=profile_sort,
            top=int(top),
            source=source,
            hotspots=tuple(hotspots),
        )
        _step_done(run_bar, "phase=profile")

    return _MeasuredRuns(run_result=baseline, samples=tuple(samples), profile=profile_result)


def _benchmark_result(
    ticks: int,
    measured: _MeasuredRuns,
    *,
    render_telemetry: ReplayRenderTelemetryResult | None = None,
) -> ReplayBenchmarkResult:
    samples = measured.samples
    return ReplayBenchmarkResult(
        ticks=ticks,
        run_result=measured.run_result,
        samples=samples,
        wall_ms=_aggregate([sample.wall_ms for sample in samples]),
        ticks_per_second=_aggregate([sample.ticks_per_second for sample in samples]),
        realtime_x=_aggregate([sample.realtime_x for sample in samples]),
        profile=measured.profile,
        render_telemetry=render_telemetry,
    )


def _validate_args(*, runs: int, warmup_runs: int, top: int) -> None:
    if int(runs) < 1:
        raise ReplayBenchmarkError("runs must be >= 1")
    if int(warmup_runs) < 0:
        raise ReplayBenchmarkError("warmup_runs must be >= 0")
    if int(top) < 1:
        raise ReplayBenchmarkError("top must be >= 1")


def _run_render_once(
    *,
    ctx: ViewContext,
    replay: Replay,
    cfg: CrimsonConfig,
    console: ConsoleState,
    max_ticks: int | None,
    rtx: bool,
    telemetry_session: RenderTelemetrySession | None = None,
    observer: PlaybackWalkObserver | None = None,
) -> _RenderOnceResult:
    mode = ReplayPlaybackMode(
        ctx,
        replay=replay,
        config=cfg,
        console=console,
        max_ticks=max_ticks,
        rtx=bool(rtx),
    )
    mode.open()
    try:
        step_dt = float(mode._dt)
        if step_dt <= 0.0:
            step_dt = 1.0 / 60.0

        frame_index = 0
        while not bool(mode.finished):
            tick_before = int(mode.tick_index)
            if telemetry_session is not None:
                telemetry_session.begin_frame(
                    frame_index=int(frame_index),
                    tick_index_before_update=int(tick_before),
                )

            frame_start_ns = time.perf_counter_ns()
            update_start_ns = time.perf_counter_ns()
            mode.update(float(step_dt))
            update_ns = max(0, int(time.perf_counter_ns()) - int(update_start_ns))

            draw_start_ns = time.perf_counter_ns()
            rl.begin_drawing()
            try:
                mode.draw()
            finally:
                rl.end_drawing()
            draw_ns = max(0, int(time.perf_counter_ns()) - int(draw_start_ns))
            frame_ns = max(0, int(time.perf_counter_ns()) - int(frame_start_ns))

            tick_after = int(mode.tick_index)
            if observer is not None:
                observer.progress(int(tick_after))
            if telemetry_session is not None:
                telemetry_session.end_frame(
                    tick_index_after_update=int(tick_after),
                    update_ms=float(update_ns) / 1_000_000.0,
                    draw_ms=float(draw_ns) / 1_000_000.0,
                    frame_ms=float(frame_ns) / 1_000_000.0,
                )

            if bool(mode.close_requested):
                raise ReplayBenchmarkError("render benchmark aborted: replay playback requested close")

            frame_index += 1

        return _RenderOnceResult(
            run_result=_run_result_for_replay_mode(mode=mode),
            telemetry_frames=(telemetry_session.frames if telemetry_session is not None else ()),
        )
    finally:
        mode.close()


def _run_result_for_replay_mode(*, mode: ReplayPlaybackMode) -> RunResult:
    driver = mode._driver
    if driver is None:
        raise ReplayBenchmarkError("render benchmark failed: replay driver was not available")
    return driver.build_result()


def _assert_consistent_run_result(expected: RunResult, actual: RunResult, *, where: str) -> None:
    mismatches = run_result_mismatches(expected, actual)
    if mismatches:
        raise ReplayBenchmarkError(
            f"non-deterministic replay result across runs: {', '.join(mismatches)} differ ({where})",
        )


def _aggregate(values: list[float]) -> BenchmarkAggregate:
    if not values:
        raise ReplayBenchmarkError("benchmark produced no samples")
    sorted_values = sorted(float(value) for value in values)
    mean_value = float(statistics.fmean(sorted_values))
    stdev_value = float(statistics.stdev(sorted_values)) if len(sorted_values) >= 2 else 0.0
    return BenchmarkAggregate(
        min=float(sorted_values[0]),
        p50=_percentile(sorted_values, 0.50),
        mean=float(mean_value),
        p95=_percentile(sorted_values, 0.95),
        max=float(sorted_values[-1]),
        stdev=float(stdev_value),
    )


def _aggregate_or_zero(values: list[float]) -> BenchmarkAggregate:
    if not values:
        return BenchmarkAggregate(min=0.0, p50=0.0, mean=0.0, p95=0.0, max=0.0, stdev=0.0)
    return _aggregate(values)


def _percentile(sorted_values: list[float], ratio: float) -> float:
    if not sorted_values:
        raise ReplayBenchmarkError("cannot compute percentile of empty values")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    clamped = min(1.0, max(0.0, float(ratio)))
    pos = (len(sorted_values) - 1) * clamped
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_values[lo])
    frac = float(pos) - float(lo)
    return float(sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac)


def _extract_hotspots(
    profile: cProfile.Profile,
    *,
    sort_key: ProfileSortKey,
    top: int,
) -> tuple[HotspotSource, list[ReplayProfileHotspot]]:
    stats_data: Any = cast(Any, pstats.Stats(profile)).stats
    rows: list[ReplayProfileHotspot] = []
    for key, values in stats_data.items():
        file_name, line_number, function_name = key
        primitive_calls, total_calls, tottime, cumtime, _callers = values
        rows.append(
            ReplayProfileHotspot(
                file=str(file_name),
                line=int(line_number),
                function=str(function_name),
                primitive_calls=int(primitive_calls),
                total_calls=int(total_calls),
                tottime=float(tottime),
                cumtime=float(cumtime),
            ),
        )

    if str(sort_key) == "tottime":
        rows.sort(key=lambda row: float(row.tottime), reverse=True)
    else:
        rows.sort(key=lambda row: float(row.cumtime), reverse=True)

    project_rows = [row for row in rows if _is_project_hotspot_path(str(row.file))]
    if project_rows:
        return "project", project_rows[: int(top)]
    return "all", rows[: int(top)]


def _is_project_hotspot_path(path: str) -> bool:
    text = str(path).replace("\\", "/").lower()
    return (
        text.startswith(("src/crimson/", "src/grim/", "crimson/", "grim/")) or "/src/crimson/" in text or "/src/grim/" in text
    )


def _top_ticks(
    *,
    frames: tuple[RenderTelemetryFrame, ...],
    top_n: int,
    key_fn: Callable[[RenderTelemetryFrame], float],
) -> tuple[ReplayRenderTelemetryTopTick, ...]:
    ordered = sorted(frames, key=key_fn, reverse=True)
    selected = ordered[: max(0, int(top_n))]
    return tuple(
        ReplayRenderTelemetryTopTick(
            tick_index=int(frame.tick_index_after_update),
            frame_index=int(frame.frame_index),
            value=float(key_fn(frame)),
        )
        for frame in selected
    )


def _summarize_render_telemetry(*, frames: tuple[RenderTelemetryFrame, ...]) -> ReplayRenderTelemetrySummary:
    frame_ms_values = [float(frame.frame_ms) for frame in frames]
    update_ms_values = [float(frame.update_ms) for frame in frames]
    draw_ms_values = [float(frame.draw_ms) for frame in frames]
    draw_calls_values = [float(frame.draw_calls_total) for frame in frames]

    return ReplayRenderTelemetrySummary(
        frame_ms=_aggregate_or_zero(frame_ms_values),
        update_ms=_aggregate_or_zero(update_ms_values),
        draw_ms=_aggregate_or_zero(draw_ms_values),
        draw_calls_total=_aggregate_or_zero(draw_calls_values),
        top_draw_ms_ticks=_top_ticks(frames=frames, top_n=5, key_fn=lambda row: float(row.draw_ms)),
        top_frame_ms_ticks=_top_ticks(frames=frames, top_n=5, key_fn=lambda row: float(row.frame_ms)),
        top_draw_calls_ticks=_top_ticks(frames=frames, top_n=5, key_fn=lambda row: float(row.draw_calls_total)),
    )
