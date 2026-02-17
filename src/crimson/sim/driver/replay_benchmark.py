from __future__ import annotations

import cProfile
import math
import pstats
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from ...replay import Replay
from .replay_runner import run_replay
from .setup import RunResult

ProfileSortKey = Literal["cumtime", "tottime"]
HotspotSource = Literal["project", "all"]


class ReplayBenchmarkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BenchmarkSample:
    wall_ms: float
    ticks_per_second: float
    realtime_x: float


@dataclass(frozen=True, slots=True)
class BenchmarkAggregate:
    min: float
    p50: float
    mean: float
    p95: float
    max: float
    stdev: float


@dataclass(frozen=True, slots=True)
class ReplayProfileHotspot:
    file: str
    line: int
    function: str
    primitive_calls: int
    total_calls: int
    tottime: float
    cumtime: float


@dataclass(frozen=True, slots=True)
class ReplayProfileResult:
    sort: ProfileSortKey
    top: int
    source: HotspotSource
    hotspots: tuple[ReplayProfileHotspot, ...]


@dataclass(frozen=True, slots=True)
class ReplayBenchmarkResult:
    run_result: RunResult
    samples: tuple[BenchmarkSample, ...]
    wall_ms: BenchmarkAggregate
    ticks_per_second: BenchmarkAggregate
    realtime_x: BenchmarkAggregate
    profile: ReplayProfileResult | None


def run_replay_benchmark(
    replay: Replay,
    *,
    runs: int = 5,
    warmup_runs: int = 1,
    max_ticks: int | None = None,
    strict_events: bool = True,
    trace_rng: bool = False,
    profile: bool = False,
    profile_sort: ProfileSortKey = "cumtime",
    top: int = 20,
    profile_out: Path | None = None,
) -> ReplayBenchmarkResult:
    if int(runs) < 1:
        raise ReplayBenchmarkError("runs must be >= 1")
    if int(warmup_runs) < 0:
        raise ReplayBenchmarkError("warmup_runs must be >= 0")
    if int(top) < 1:
        raise ReplayBenchmarkError("top must be >= 1")

    for _ in range(int(warmup_runs)):
        run_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
        )

    baseline_result: RunResult | None = None
    samples: list[BenchmarkSample] = []
    for sample_idx in range(int(runs)):
        start_ns = time.perf_counter_ns()
        result = run_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
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

    assert baseline_result is not None
    profile_result: ReplayProfileResult | None = None
    if bool(profile):
        prof = cProfile.Profile()
        prof.enable()
        prof_result = run_replay(
            replay,
            max_ticks=max_ticks,
            strict_events=bool(strict_events),
            trace_rng=bool(trace_rng),
        )
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


def _assert_consistent_run_result(expected: RunResult, actual: RunResult, *, where: str) -> None:
    fields = (
        "game_mode_id",
        "tick_rate",
        "ticks",
        "elapsed_ms",
        "score_xp",
        "creature_kill_count",
        "most_used_weapon_id",
        "shots_fired",
        "shots_hit",
        "rng_state",
    )
    for field_name in fields:
        exp = int(getattr(expected, field_name))
        got = int(getattr(actual, field_name))
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
    stats = cast(Any, pstats.Stats(profile))
    rows: list[ReplayProfileHotspot] = []
    for key, values in cast(dict[tuple[str, int, str], tuple[int, int, float, float, object]], stats.stats).items():
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
