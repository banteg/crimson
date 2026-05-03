from __future__ import annotations

import cProfile
import json
import math
import pstats
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import msgspec
from tqdm import tqdm

from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.raylib_api import rl
from grim.view import ViewContext

from ...modes.replay_playback_mode import ReplayPlaybackMode
from ...replay import Replay
from .playback_driver import PlaybackWalkObserver, build_verify_playback_driver
from .render_telemetry import RenderTelemetryFrameSnapshot, RenderTelemetrySession
from .render_telemetry_charts import write_render_telemetry_charts
from .setup import RunResult

ProfileSortKey = Literal["cumtime", "tottime"]
HotspotSource = Literal["project", "all"]
ReplayBenchmarkPhase = Literal["warmup", "measure", "profile", "telemetry"]


class ReplayBenchmarkTickProgress(PlaybackWalkObserver):
    tick_total: int
    completed_ticks: int = 0

    def _advance(self, value: int) -> None:
        _ = value

    def progress(self, next_tick_index: int) -> None:
        target_tick = max(0, min(int(self.tick_total), int(next_tick_index)))
        if target_tick <= int(self.completed_ticks):
            return
        self._advance(target_tick - int(self.completed_ticks))
        self.completed_ticks = target_tick

    def complete(self) -> None:
        self.progress(int(self.tick_total))

    def close(self) -> None:
        return None


class ReplayBenchmarkProgress(msgspec.Struct):
    def begin_ticks(self, *, tick_desc: str, tick_total: int) -> ReplayBenchmarkTickProgress | None:
        _ = tick_desc, tick_total
        return None

    def complete_step(
        self,
        *,
        phase: ReplayBenchmarkPhase,
        sample_index: int | None = None,
        sample_count: int | None = None,
    ) -> None:
        _ = phase, sample_index, sample_count

    def close(self) -> None:
        return None


class _TqdmReplayBenchmarkTickProgress(ReplayBenchmarkTickProgress):
    tick_bar: Any = None

    def _advance(self, value: int) -> None:
        self.tick_bar.update(int(value))

    def close(self) -> None:
        self.tick_bar.close()


class _TqdmReplayBenchmarkProgress(ReplayBenchmarkProgress):
    run_bar: Any
    tqdm_factory: Any = tqdm

    def begin_ticks(self, *, tick_desc: str, tick_total: int) -> ReplayBenchmarkTickProgress | None:
        if int(tick_total) <= 0:
            return None
        return _TqdmReplayBenchmarkTickProgress(
            tick_total=int(tick_total),
            tick_bar=self.tqdm_factory(
                total=int(tick_total),
                unit="tick",
                desc=str(tick_desc),
                leave=False,
            ),
        )

    def complete_step(
        self,
        *,
        phase: ReplayBenchmarkPhase,
        sample_index: int | None = None,
        sample_count: int | None = None,
    ) -> None:
        self.run_bar.update(1)
        postfix = f"phase={phase}"
        if phase == "measure" and sample_index is not None and sample_count is not None:
            postfix = f"{postfix} sample={int(sample_index)}/{int(sample_count)}"
        self.run_bar.set_postfix_str(postfix, refresh=False)

    def close(self) -> None:
        self.run_bar.close()


def _replay_benchmark_progress(
    *,
    show_progress: bool,
    planned_steps: int,
    desc: str,
) -> ReplayBenchmarkProgress:
    if not bool(show_progress) or int(planned_steps) <= 0:
        return ReplayBenchmarkProgress()
    return _TqdmReplayBenchmarkProgress(
        run_bar=tqdm(
            total=int(planned_steps),
            unit="run",
            desc=str(desc),
            leave=False,
        ),
    )


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


class ReplayRenderTelemetryFrame(msgspec.Struct, frozen=True):
    frame_index: int
    tick_index_before_update: int
    tick_index_after_update: int
    update_ms: float
    draw_ms: float
    frame_ms: float
    draw_calls_total: int
    draw_calls_by_api: dict[str, int]
    draw_calls_by_pass: dict[str, int]
    pass_ms: dict[str, float]


class ReplayRenderTelemetrySummary(msgspec.Struct, frozen=True):
    frame_ms: BenchmarkAggregate
    update_ms: BenchmarkAggregate
    draw_ms: BenchmarkAggregate
    draw_calls_total: BenchmarkAggregate
    top_draw_ms_ticks: tuple[ReplayRenderTelemetryTopTick, ...]
    top_frame_ms_ticks: tuple[ReplayRenderTelemetryTopTick, ...]
    top_draw_calls_ticks: tuple[ReplayRenderTelemetryTopTick, ...]


class ReplayRenderTelemetryArtifacts(msgspec.Struct, frozen=True):
    telemetry_json_path: Path | None = None
    charts_dir: Path | None = None
    frame_timing_svg: Path | None = None
    draw_calls_svg: Path | None = None
    pass_timing_stacked_svg: Path | None = None
    report_md: Path | None = None


class ReplayRenderTelemetryResult(msgspec.Struct, frozen=True):
    frames: tuple[ReplayRenderTelemetryFrame, ...]
    summary: ReplayRenderTelemetrySummary
    artifacts: ReplayRenderTelemetryArtifacts | None = None
    preview: tuple[ReplayRenderTelemetryFrame, ...] = ()


class ReplayBenchmarkResult(msgspec.Struct, frozen=True):
    run_result: RunResult
    samples: tuple[BenchmarkSample, ...]
    wall_ms: BenchmarkAggregate
    ticks_per_second: BenchmarkAggregate
    realtime_x: BenchmarkAggregate
    profile: ReplayProfileResult | None
    render_telemetry: ReplayRenderTelemetryResult | None = None


class _RenderOnceResult(msgspec.Struct, frozen=True):
    run_result: RunResult
    telemetry_frames: tuple[RenderTelemetryFrameSnapshot, ...] = ()


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
    trace_rng: bool = False,
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
    from grim.config import ensure_crimson_cfg
    from grim.console import create_console
    from grim.raylib_api import rl

    from ...assets_fetch import download_missing_paqs

    _validate_args(runs=runs, warmup_runs=warmup_runs, top=top)
    telemetry_requested = bool(
        render_telemetry
        or render_telemetry_out is not None
        or render_charts_out_dir is not None,
    )

    baseline_result = build_verify_playback_driver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
    ).run()

    runtime_base_dir = Path(base_dir)
    runtime_assets_dir = Path(assets_dir) if assets_dir is not None else runtime_base_dir
    runtime_base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(runtime_base_dir)
    if bool(mute_audio):
        cfg.audio.sound_disabled = True
        cfg.audio.music_disabled = True

    render_width = int(width) if width is not None else cfg.display.width
    render_height = int(height) if height is not None else cfg.display.height
    if int(render_width) <= 0 or int(render_height) <= 0:
        raise ReplayBenchmarkError(
            f"invalid render resolution: {render_width}x{render_height}; width/height must be > 0",
        )

    console = create_console(runtime_base_dir, assets_dir=runtime_assets_dir)
    download_missing_paqs(runtime_assets_dir, console)
    ctx = ViewContext(assets_dir=runtime_assets_dir, preserve_bugs=False)

    config_flags = rl.ConfigFlags.FLAG_WINDOW_HIDDEN
    if int(config_flags) != 0:
        rl.set_config_flags(int(config_flags))
    resources = None
    window_open = False
    try:
        rl.init_window(int(render_width), int(render_height), f"Replay Benchmark - {Path(replay_path).name}")
        window_open = True
    except RuntimeError as exc:
        raise ReplayBenchmarkError(f"render benchmark could not initialize window: {exc}") from exc

    tick_total = len(replay.ticks)
    if max_ticks is not None:
        tick_total = min(tick_total, max(0, int(max_ticks)))

    progress = ReplayBenchmarkProgress()
    try:
        resources = load_runtime_resources(runtime_assets_dir)
        planned_steps = int(warmup_runs) + int(runs) + (1 if bool(profile) else 0) + (1 if telemetry_requested else 0)
        progress = _replay_benchmark_progress(
            show_progress=bool(show_progress),
            planned_steps=planned_steps,
            desc="render benchmark",
        )

        def _run_once_with_progress(
            *,
            tick_desc: str,
            rtx: bool,
            telemetry_session: RenderTelemetrySession | None = None,
        ) -> _RenderOnceResult:
            tick_progress = progress.begin_ticks(
                tick_desc=str(tick_desc),
                tick_total=tick_total,
            )
            completed_run = False
            try:
                result = _run_render_once(
                    ctx=ctx,
                    replay_path=replay_path,
                    cfg=cfg,
                    console=console,
                    max_ticks=max_ticks,
                    trace_rng=bool(trace_rng),
                    rtx=bool(rtx),
                    telemetry_session=telemetry_session,
                    observer=tick_progress,
                )
                completed_run = True
                return result
            finally:
                if tick_progress is not None:
                    if completed_run:
                        tick_progress.complete()
                    tick_progress.close()

        for _ in range(int(warmup_runs)):
            _run_once_with_progress(
                tick_desc="render ticks warmup",
                rtx=bool(rtx),
            )
            progress.complete_step(phase="warmup")

        samples: list[BenchmarkSample] = []
        for sample_idx in range(int(runs)):
            start_ns = time.perf_counter_ns()
            measured = _run_once_with_progress(
                tick_desc=f"render ticks sample {sample_idx + 1}/{int(runs)}",
                rtx=bool(rtx),
            )
            elapsed_ns = max(1, int(time.perf_counter_ns()) - int(start_ns))
            wall_ms = float(elapsed_ns) / 1_000_000.0
            wall_s = float(elapsed_ns) / 1_000_000_000.0
            ticks_per_second = float(measured.run_result.ticks) / wall_s
            realtime_x = float(measured.run_result.elapsed_ms) / wall_ms
            samples.append(
                BenchmarkSample(
                    wall_ms=float(wall_ms),
                    ticks_per_second=float(ticks_per_second),
                    realtime_x=float(realtime_x),
                ),
            )
            _assert_consistent_run_result(
                baseline_result,
                measured.run_result,
                where=f"render run {sample_idx + 1}",
            )
            progress.complete_step(
                phase="measure",
                sample_index=sample_idx + 1,
                sample_count=int(runs),
            )

        profile_result: ReplayProfileResult | None = None
        if bool(profile):
            prof = cProfile.Profile()
            prof.enable()
            profiled = _run_once_with_progress(
                tick_desc="render ticks profile",
                rtx=bool(rtx),
            )
            prof.disable()
            _assert_consistent_run_result(
                baseline_result,
                profiled.run_result,
                where="render profiled run",
            )

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
            progress.complete_step(phase="profile")

        telemetry_result: ReplayRenderTelemetryResult | None = None
        if telemetry_requested:
            telemetry_session = RenderTelemetrySession()
            with telemetry_session:
                collected = _run_once_with_progress(
                    tick_desc="render ticks telemetry",
                    rtx=bool(rtx),
                    telemetry_session=telemetry_session,
                )
            _assert_consistent_run_result(
                baseline_result,
                collected.run_result,
                where="render telemetry run",
            )

            frames = tuple(_convert_telemetry_frame(frame) for frame in collected.telemetry_frames)
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
                telemetry_json_path=telemetry_json_path,
                charts_dir=(Path(render_charts_out_dir) if render_charts_out_dir is not None else None),
                frame_timing_svg=chart_paths.get("frame_timing_svg"),
                draw_calls_svg=chart_paths.get("draw_calls_svg"),
                pass_timing_stacked_svg=chart_paths.get("pass_timing_stacked_svg"),
                report_md=chart_paths.get("report_md"),
            )
            telemetry_result = ReplayRenderTelemetryResult(
                frames=frames,
                summary=summary,
                artifacts=artifacts,
                preview=tuple(frames[:10]),
            )
            progress.complete_step(phase="telemetry")
    finally:
        progress.close()
        unload_runtime_resources(resources)
        if window_open:
            rl.close_window()

    wall_values = [sample.wall_ms for sample in samples]
    tps_values = [sample.ticks_per_second for sample in samples]
    realtime_values = [sample.realtime_x for sample in samples]

    return ReplayBenchmarkResult(
        run_result=baseline_result,
        samples=tuple(samples),
        wall_ms=_aggregate(wall_values),
        ticks_per_second=_aggregate(tps_values),
        realtime_x=_aggregate(realtime_values),
        profile=profile_result,
        render_telemetry=telemetry_result,
    )


def run_replay_benchmark(
    replay: Replay,
    *,
    runs: int = 5,
    warmup_runs: int = 1,
    max_ticks: int | None = None,
    trace_rng: bool = False,
    profile: bool = False,
    profile_sort: ProfileSortKey = "cumtime",
    top: int = 20,
    profile_out: Path | None = None,
    show_progress: bool = False,
) -> ReplayBenchmarkResult:
    _validate_args(runs=runs, warmup_runs=warmup_runs, top=top)

    tick_total = len(replay.ticks)
    if max_ticks is not None:
        tick_total = min(tick_total, max(0, int(max_ticks)))

    progress = ReplayBenchmarkProgress()
    try:
        planned_steps = int(warmup_runs) + int(runs) + (1 if bool(profile) else 0)
        progress = _replay_benchmark_progress(
            show_progress=bool(show_progress),
            planned_steps=planned_steps,
            desc="headless benchmark",
        )

        def _run_once_with_progress(*, tick_desc: str) -> RunResult:
            tick_progress = progress.begin_ticks(
                tick_desc=str(tick_desc),
                tick_total=tick_total,
            )
            completed_run = False

            try:
                driver = build_verify_playback_driver(
                    replay,
                    max_ticks=max_ticks,
                    trace_rng=bool(trace_rng),
                )
                result = driver.run(
                    observer=tick_progress,
                )
                completed_run = True
                return result
            finally:
                if tick_progress is not None:
                    if completed_run:
                        tick_progress.complete()
                    tick_progress.close()

        for _ in range(int(warmup_runs)):
            _run_once_with_progress(tick_desc="headless ticks warmup")
            progress.complete_step(phase="warmup")

        baseline_result: RunResult | None = None
        samples: list[BenchmarkSample] = []
        for sample_idx in range(int(runs)):
            start_ns = time.perf_counter_ns()
            result = _run_once_with_progress(
                tick_desc=f"headless ticks sample {sample_idx + 1}/{int(runs)}",
            )
            elapsed_ns = max(1, int(time.perf_counter_ns()) - int(start_ns))
            wall_ms = float(elapsed_ns) / 1_000_000.0
            wall_s = float(elapsed_ns) / 1_000_000_000.0
            ticks_per_second = float(result.ticks) / wall_s
            realtime_x = float(result.elapsed_ms) / wall_ms
            samples.append(
                BenchmarkSample(
                    wall_ms=float(wall_ms),
                    ticks_per_second=float(ticks_per_second),
                    realtime_x=float(realtime_x),
                ),
            )
            if baseline_result is None:
                baseline_result = result
            else:
                _assert_consistent_run_result(baseline_result, result, where=f"measured run {sample_idx + 1}")
            progress.complete_step(
                phase="measure",
                sample_index=sample_idx + 1,
                sample_count=int(runs),
            )

        assert baseline_result is not None
        profile_result: ReplayProfileResult | None = None
        if bool(profile):
            prof = cProfile.Profile()
            prof.enable()
            prof_result = _run_once_with_progress(tick_desc="headless ticks profile")
            prof.disable()
            _assert_consistent_run_result(baseline_result, prof_result, where="profiled run")

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
            progress.complete_step(phase="profile")
    finally:
        progress.close()

    wall_values = [sample.wall_ms for sample in samples]
    tps_values = [sample.ticks_per_second for sample in samples]
    realtime_values = [sample.realtime_x for sample in samples]

    return ReplayBenchmarkResult(
        run_result=baseline_result,
        samples=tuple(samples),
        wall_ms=_aggregate(wall_values),
        ticks_per_second=_aggregate(tps_values),
        realtime_x=_aggregate(realtime_values),
        profile=profile_result,
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
    replay_path: Path,
    cfg: CrimsonConfig,
    console: ConsoleState,
    max_ticks: int | None,
    trace_rng: bool,
    rtx: bool,
    telemetry_session: RenderTelemetrySession | None = None,
    observer: PlaybackWalkObserver | None = None,
) -> _RenderOnceResult:
    mode = ReplayPlaybackMode(
        ctx,
        replay_path=Path(replay_path),
        config=cfg,
        console=console,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        rtx=bool(rtx),
    )
    mode.open()
    try:
        replay = mode._replay
        if replay is None:
            raise ReplayBenchmarkError("render benchmark failed: replay playback did not initialize replay state")

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
    return driver.build_run_result(ticks=int(mode.tick_index))


def _assert_consistent_run_result(expected: RunResult, actual: RunResult, *, where: str) -> None:
    expected_values = (
        (expected.game_mode_id, actual.game_mode_id, "game_mode_id"),
        (expected.tick_rate, actual.tick_rate, "tick_rate"),
        (expected.ticks, actual.ticks, "ticks"),
        (expected.elapsed_ms, actual.elapsed_ms, "elapsed_ms"),
        (expected.score_xp, actual.score_xp, "score_xp"),
        (expected.creature_kill_count, actual.creature_kill_count, "creature_kill_count"),
        (expected.most_used_weapon_id, actual.most_used_weapon_id, "most_used_weapon_id"),
        (expected.shots_fired, actual.shots_fired, "shots_fired"),
        (expected.shots_hit, actual.shots_hit, "shots_hit"),
        (expected.rng_state, actual.rng_state, "rng_state"),
    )
    for exp, got, field_name in expected_values:
        if int(exp) != int(got):
            raise ReplayBenchmarkError(
                "non-deterministic replay result across runs: "
                f"{field_name} expected={exp} actual={got} ({where})",
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
    stats_data: Any = getattr(pstats.Stats(profile), "stats")
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
        text.startswith("src/crimson/")
        or text.startswith("src/grim/")
        or text.startswith("crimson/")
        or text.startswith("grim/")
        or "/src/crimson/" in text
        or "/src/grim/" in text
    )


def _convert_telemetry_frame(frame: RenderTelemetryFrameSnapshot) -> ReplayRenderTelemetryFrame:
    return ReplayRenderTelemetryFrame(
        frame_index=int(frame.frame_index),
        tick_index_before_update=int(frame.tick_index_before_update),
        tick_index_after_update=int(frame.tick_index_after_update),
        update_ms=float(frame.update_ms),
        draw_ms=float(frame.draw_ms),
        frame_ms=float(frame.frame_ms),
        draw_calls_total=int(frame.draw_calls_total),
        draw_calls_by_api={str(key): int(value) for key, value in frame.draw_calls_by_api.items()},
        draw_calls_by_pass={str(key): int(value) for key, value in frame.draw_calls_by_pass.items()},
        pass_ms={str(key): float(value) for key, value in frame.pass_ms.items()},
    )


def _top_ticks(
    *,
    frames: tuple[ReplayRenderTelemetryFrame, ...],
    top_n: int,
    key_fn: Callable[[ReplayRenderTelemetryFrame], float],
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


def _summarize_render_telemetry(*, frames: tuple[ReplayRenderTelemetryFrame, ...]) -> ReplayRenderTelemetrySummary:
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
