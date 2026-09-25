from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast

import msgspec
import typer
from tqdm import tqdm

from ..game_modes import GameMode
from ..paths import default_runtime_dir
from ..quests.level import QuestLevel

if TYPE_CHECKING:
    from ..dbg.checkpoint_diff import ReplayDiffResult
    from ..replay import Replay
    from ..replay.driver.progress import ReplayRenderPhase, ReplayRenderProgress
    from ..replay.driver.replay_benchmark import (
        BenchmarkAggregate,
        BenchmarkSample,
        ReplayProfileResult,
        ReplayRenderTelemetryArtifacts,
        ReplayRenderTelemetryFrame,
        ReplayRenderTelemetryTopTick,
    )
    from ..replay.driver.replay_info import ReplayInfoResult, ReplayInfoTimelineEvent
    from ..sim.run_result import RunResult

_REPLAY_VERIFY_SCHEMA_VERSION = 3
_REPLAY_INFO_SCHEMA_VERSION = 2
_REPLAY_BENCHMARK_SCHEMA_VERSION = 3
_REPLAY_VERIFY_MISMATCH_EXIT_CODE = 3


class _ProgressBarLike(Protocol):
    total: int

    def update(self, value: int) -> None: ...

    def set_postfix(self, *, refresh: bool = True, **kwargs: object) -> None: ...

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


class _ReplayRenderProgressBars(msgspec.Struct):
    total_ticks: int
    render_audio: bool
    tqdm_factory: Callable[..., _ProgressBarLike]
    video_bar: _ProgressBarLike
    audio_bar: _ProgressBarLike | None = None
    video_last_tick: int = 0
    audio_last_tick: int = 0

    def _ensure_audio_bar(self, total: int) -> _ProgressBarLike:
        if self.audio_bar is not None:
            return self.audio_bar
        self.audio_bar = self.tqdm_factory(
            total=int(total),
            unit="tick",
            desc="replay audio",
            leave=True,
        )
        return self.audio_bar

    def update(
        self,
        *,
        phase: ReplayRenderPhase,
        frame_count: int,
        tick_index: int,
        total_ticks: int,
    ) -> None:
        resolved_total = int(self.total_ticks)
        if int(total_ticks) > 0:
            resolved_total = int(total_ticks)
        if int(resolved_total) <= 0:
            return
        if phase == "video":
            bar = self.video_bar
            last_tick = int(self.video_last_tick)
        elif phase == "audio":
            if not bool(self.render_audio):
                return
            bar = self._ensure_audio_bar(int(resolved_total))
            last_tick = int(self.audio_last_tick)
        else:
            return
        if int(bar.total) != int(resolved_total):
            bar.total = int(resolved_total)
        tick = min(int(resolved_total), max(0, int(tick_index)))
        delta = int(tick) - int(last_tick)
        if int(delta) <= 0:
            return
        bar.update(int(delta))
        if phase == "video":
            bar.set_postfix(frames=int(frame_count), refresh=False)
            self.video_last_tick = int(tick)
        else:
            self.audio_last_tick = int(tick)

    def close(self) -> None:
        self.video_bar.close()
        if self.audio_bar is not None:
            self.audio_bar.close()


def _replay_render_progress_runtime(
    *,
    total_ticks: int,
    render_audio: bool,
    tqdm_factory: Callable[..., _ProgressBarLike] = tqdm,
) -> ReplayRenderProgress | None:
    if int(total_ticks) <= 0:
        return None
    return cast(
        "ReplayRenderProgress",
        _ReplayRenderProgressBars(
            total_ticks=int(total_ticks),
            render_audio=bool(render_audio),
            tqdm_factory=tqdm_factory,
            video_bar=tqdm_factory(
                total=int(total_ticks),
                unit="tick",
                desc="replay video",
                leave=True,
            ),
        ),
    )


def _render_checkpoint_diff_failure(diff: ReplayDiffResult) -> None:
    from ..dbg.checkpoint_diff import checkpoint_deepdiff

    failure = diff.failure
    assert failure is not None
    exp = failure.expected
    act = failure.actual

    if failure.kind == "missing_checkpoint":
        typer.echo(f"checkpoint missing at tick={int(failure.tick_index)}", err=True)
        raise typer.Exit(code=1)
    if failure.kind == "extra_checkpoint":
        typer.echo(f"unexpected checkpoint at tick={int(failure.tick_index)}", err=True)
        raise typer.Exit(code=1)

    assert exp is not None
    assert act is not None
    typer.echo(f"checkpoint mismatch at tick={int(failure.tick_index)}", err=True)
    typer.echo(f"  rng_state expected={exp.rng_state} actual={act.rng_state}", err=True)
    typer.echo(f"  elapsed_ms expected={exp.elapsed_ms} actual={act.elapsed_ms}", err=True)
    typer.echo(f"  score_xp expected={exp.score_xp} actual={act.score_xp}", err=True)
    typer.echo(f"  kills expected={exp.kills} actual={act.kills}", err=True)
    typer.echo(f"  creature_count expected={exp.creature_count} actual={act.creature_count}", err=True)
    typer.echo(f"  perk_pending expected={exp.perk_pending} actual={act.perk_pending}", err=True)
    deepdiff = checkpoint_deepdiff(exp, act)
    if deepdiff is not None:
        mismatches = deepdiff.payload.get("mismatches") if isinstance(deepdiff.payload, dict) else None
        if isinstance(mismatches, list) and mismatches:
            first = mismatches[0]
            if isinstance(first, dict):
                path = str(first.get("path", "<unknown>"))
                if first.get("kind") == "length_mismatch":
                    path = f"{path}._len"
                typer.echo(
                    f"  first state diff: {path} expected={first.get('expected')!r} actual={first.get('actual')!r}",
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
        if exp.events.hit_head or act.events.hit_head:
            typer.echo(
                f"  hit head expected={exp.events.hit_head[:8]} actual={act.events.hit_head[:8]}",
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


def _replay_mode_label(game_mode_id: GameMode) -> str:
    match game_mode_id:
        case GameMode.SURVIVAL:
            return "survival"
        case GameMode.RUSH:
            return "rush"
        case GameMode.QUESTS:
            return "quests"
        case _:
            return "unknown"


class _ReplayVerifyPayload(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    status: Literal["ok", "result_mismatch", "partial"]
    replay: str
    payload_sha256: str
    game_version: str
    ticks: int
    ticks_simulated: int
    result: RunResult
    recorded: RunResult
    mismatched_fields: list[str]


class _ReplayInfoSummaryPayload(msgspec.Struct, forbid_unknown_fields=True):
    game_mode_id: GameMode
    tick_rate: int
    ticks_simulated: int
    elapsed_ms: int
    player_count: int
    event_count: int
    event_counts_by_kind: dict[str, int]


class _ReplayInfoEventPayload(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    elapsed_ms: int
    elapsed_s: float
    kind: str
    player_index: int | None
    detail: str
    data: dict[str, object]


class _ReplayInfoPayload(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    status: str
    replay: str
    summary: _ReplayInfoSummaryPayload
    timeline: list[_ReplayInfoEventPayload]


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
    trace_rng: bool
    profile: bool
    profile_sort: str
    top: int
    profile_out: str | None
    render_telemetry: bool
    render_telemetry_out: str | None
    render_charts_out_dir: str | None


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


class _ReplayRenderTelemetryTopTickPayload(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    frame_index: int
    value: float


class _ReplayRenderTelemetryFramePayload(msgspec.Struct, forbid_unknown_fields=True):
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


class _ReplayRenderTelemetrySummaryPayload(msgspec.Struct, forbid_unknown_fields=True):
    frame_ms: _BenchmarkAggregatePayload
    update_ms: _BenchmarkAggregatePayload
    draw_ms: _BenchmarkAggregatePayload
    draw_calls_total: _BenchmarkAggregatePayload
    top_draw_ms_ticks: list[_ReplayRenderTelemetryTopTickPayload]
    top_frame_ms_ticks: list[_ReplayRenderTelemetryTopTickPayload]
    top_draw_calls_ticks: list[_ReplayRenderTelemetryTopTickPayload]


class _ReplayRenderTelemetryArtifactsPayload(msgspec.Struct, forbid_unknown_fields=True):
    telemetry_json_path: str | None
    charts_dir: str | None
    frame_timing_svg: str | None
    draw_calls_svg: str | None
    pass_timing_stacked_svg: str | None
    report_md: str | None


class _ReplayRenderTelemetryPayload(msgspec.Struct, forbid_unknown_fields=True):
    summary: _ReplayRenderTelemetrySummaryPayload
    frames: list[_ReplayRenderTelemetryFramePayload]
    preview: list[_ReplayRenderTelemetryFramePayload]
    artifacts: _ReplayRenderTelemetryArtifactsPayload | None


class _ReplayBenchmarkPayload(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    status: str
    replay: str
    settings: _ReplayBenchmarkSettingsPayload
    ticks: int
    run_result: RunResult
    benchmark: _ReplayBenchmarkSummaryPayload
    profile: _ReplayBenchmarkProfilePayload | None
    render_telemetry: _ReplayRenderTelemetryPayload | None


def _replay_info_event_payload(event: ReplayInfoTimelineEvent) -> _ReplayInfoEventPayload:
    return _ReplayInfoEventPayload(
        tick_index=event.tick_index,
        elapsed_ms=event.elapsed_ms,
        elapsed_s=event.elapsed_ms / 1000.0,
        kind=str(event.kind),
        player_index=event.player_index,
        detail=event.detail,
        data=event.data,
    )


def _replay_info_summary_payload(
    result: ReplayInfoResult,
    *,
    event_count: int,
    event_counts_by_kind: dict[str, int],
) -> _ReplayInfoSummaryPayload:
    return _ReplayInfoSummaryPayload(
        game_mode_id=result.game_mode_id,
        tick_rate=result.tick_rate,
        ticks_simulated=result.ticks_simulated,
        elapsed_ms=result.elapsed_ms,
        player_count=result.player_count,
        event_count=event_count,
        event_counts_by_kind=event_counts_by_kind,
    )


def _benchmark_aggregate_payload(aggregate: BenchmarkAggregate) -> _BenchmarkAggregatePayload:
    return _BenchmarkAggregatePayload(
        min=aggregate.min,
        p50=aggregate.p50,
        mean=aggregate.mean,
        p95=aggregate.p95,
        max=aggregate.max,
        stdev=aggregate.stdev,
    )


def _render_telemetry_top_tick_payload(entry: ReplayRenderTelemetryTopTick) -> _ReplayRenderTelemetryTopTickPayload:
    return _ReplayRenderTelemetryTopTickPayload(
        tick_index=entry.tick_index,
        frame_index=entry.frame_index,
        value=entry.value,
    )


def _render_telemetry_frame_payload(entry: ReplayRenderTelemetryFrame) -> _ReplayRenderTelemetryFramePayload:
    return _ReplayRenderTelemetryFramePayload(
        frame_index=entry.frame_index,
        tick_index_before_update=entry.tick_index_before_update,
        tick_index_after_update=entry.tick_index_after_update,
        update_ms=entry.update_ms,
        draw_ms=entry.draw_ms,
        frame_ms=entry.frame_ms,
        draw_calls_total=entry.draw_calls_total,
        draw_calls_by_api=dict(entry.draw_calls_by_api),
        draw_calls_by_pass=dict(entry.draw_calls_by_pass),
        pass_ms=dict(entry.pass_ms),
    )


def _path_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return str(path)


def _replay_benchmark_profile_payload(profile: ReplayProfileResult | None) -> _ReplayBenchmarkProfilePayload | None:
    if profile is None:
        return None
    return _ReplayBenchmarkProfilePayload(
        sort=str(profile.sort),
        top=profile.top,
        source=str(profile.source),
        hotspots=[
            _ReplayBenchmarkProfileHotspotPayload(
                file=row.file,
                line=row.line,
                function=row.function,
                primitive_calls=row.primitive_calls,
                total_calls=row.total_calls,
                tottime=row.tottime,
                cumtime=row.cumtime,
            )
            for row in profile.hotspots
        ],
    )


def _replay_benchmark_settings_payload(
    *,
    mode: Literal["headless", "render"],
    runs: int,
    warmup_runs: int,
    max_ticks: int | None,
    trace_rng: bool,
    profile: bool,
    profile_sort: Literal["cumtime", "tottime"],
    top: int,
    profile_out: Path | None,
    render_telemetry: bool,
    render_telemetry_out: Path | None,
    render_charts_out_dir: Path | None,
) -> _ReplayBenchmarkSettingsPayload:
    return _ReplayBenchmarkSettingsPayload(
        mode=mode,
        runs=runs,
        warmup_runs=warmup_runs,
        max_ticks=max_ticks,
        trace_rng=trace_rng,
        profile=profile,
        profile_sort=profile_sort,
        top=top,
        profile_out=_path_text(profile_out),
        render_telemetry=render_telemetry,
        render_telemetry_out=_path_text(render_telemetry_out),
        render_charts_out_dir=_path_text(render_charts_out_dir),
    )


def _replay_benchmark_sample_payload(sample: BenchmarkSample) -> _ReplayBenchmarkSamplePayload:
    return _ReplayBenchmarkSamplePayload(
        wall_ms=sample.wall_ms,
        ticks_per_second=sample.ticks_per_second,
        realtime_x=sample.realtime_x,
    )


def _render_telemetry_artifacts_payload(
    artifacts: ReplayRenderTelemetryArtifacts | None,
) -> _ReplayRenderTelemetryArtifactsPayload | None:
    if artifacts is None:
        return None
    return _ReplayRenderTelemetryArtifactsPayload(
        telemetry_json_path=_path_text(artifacts.telemetry_json_path),
        charts_dir=_path_text(artifacts.charts_dir),
        frame_timing_svg=_path_text(artifacts.frame_timing_svg),
        draw_calls_svg=_path_text(artifacts.draw_calls_svg),
        pass_timing_stacked_svg=_path_text(artifacts.pass_timing_stacked_svg),
        report_md=_path_text(artifacts.report_md),
    )


def _fmt_metric_agg(name: str, aggregate: BenchmarkAggregate, *, digits: int) -> str:
    entry = aggregate
    return (
        f"{name} "
        f"min={float(entry.min):.{digits}f} "
        f"p50={float(entry.p50):.{digits}f} "
        f"mean={float(entry.mean):.{digits}f} "
        f"p95={float(entry.p95):.{digits}f} "
        f"max={float(entry.max):.{digits}f} "
        f"stdev={float(entry.stdev):.{digits}f}"
    )


@dataclass(frozen=True, slots=True)
class _ReplayListRow:
    replay: str
    mode: str
    game_mode_id: GameMode | None
    game_version: str
    ticks: str
    duration: str
    score_xp: str
    kills: str
    modified: str
    modified_ts: float
    old_version: bool


def _fmt_replay_list_duration(*, ticks: int) -> str:
    from ..replay import REPLAY_TICK_RATE

    total_seconds = float(ticks) / float(REPLAY_TICK_RATE)
    if total_seconds >= 3600.0:
        hours = int(total_seconds // 3600.0)
        minutes = int((total_seconds % 3600.0) // 60.0)
        seconds = int(total_seconds % 60.0)
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    if total_seconds >= 60.0:
        minutes = int(total_seconds // 60.0)
        seconds = int(total_seconds % 60.0)
        return f"{minutes:d}:{seconds:02d}"
    return f"{total_seconds:.1f}s"


def _fmt_replay_list_modified(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M")


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", str(value)))


def _is_version_older(*, replay_version: str, current_version: str) -> bool:
    replay_parts = _version_tuple(replay_version)
    current_parts = _version_tuple(current_version)
    if not replay_parts or not current_parts:
        return False
    width = max(len(replay_parts), len(current_parts))
    replay_norm = replay_parts + (0,) * (width - len(replay_parts))
    current_norm = current_parts + (0,) * (width - len(current_parts))
    return replay_norm < current_norm


def _replay_list_mode_label(
    *,
    game_mode_id: GameMode,
    player_count: int,
    quest_level: QuestLevel | None,
) -> str:
    match game_mode_id:
        case GameMode.QUESTS:
            label = "quest"
            if quest_level is not None:
                label = f"{label} {quest_level.text}"
        case _:
            label = _replay_mode_label(game_mode_id)
    if int(player_count) > 1:
        label = f"{label} {int(player_count)}p"
    return label


def _replay_list_mode_style(game_mode_id: GameMode | None) -> str:
    match game_mode_id:
        case GameMode.SURVIVAL:
            return "green"
        case GameMode.RUSH:
            return "magenta"
        case GameMode.QUESTS:
            return "cyan"
        case GameMode.TYPO:
            return "blue"
        case GameMode.TUTORIAL:
            return "white"
        case _:
            return "white"


def _replay_list_score_kills(
    *,
    replay: Replay,
) -> tuple[str, str]:
    return str(int(replay.result.players[0].experience)), str(int(replay.result.kills))


def _build_replay_list_row(
    replay_path: Path,
    *,
    replays_dir: Path,
    load_replay_fn: Callable[[bytes], Replay],
    current_version: str,
) -> tuple[_ReplayListRow, str | None]:
    rel = str(replay_path.relative_to(replays_dir))
    modified_text = "?"
    modified_ts = 0.0
    try:
        stat = replay_path.stat()
        modified_ts = float(stat.st_mtime)
        modified_text = _fmt_replay_list_modified(modified_ts)
    except OSError as exc:
        return (
            _ReplayListRow(
                replay=rel,
                mode="error",
                game_mode_id=None,
                game_version="-",
                ticks="-",
                duration="-",
                score_xp="-",
                kills="-",
                modified=modified_text,
                modified_ts=float(modified_ts),
                old_version=False,
            ),
            str(exc).replace("\n", " ").strip(),
        )

    try:
        replay = load_replay_fn(replay_path.read_bytes())
    except (OSError, ValueError) as exc:
        return (
            _ReplayListRow(
                replay=rel,
                mode="invalid",
                game_mode_id=None,
                game_version="-",
                ticks="-",
                duration="-",
                score_xp="-",
                kills="-",
                modified=modified_text,
                modified_ts=float(modified_ts),
                old_version=False,
            ),
            str(exc).replace("\n", " ").strip(),
        )

    run = replay.run
    game_mode_id = run.game_mode_id
    ticks = len(replay.ticks)
    game_version = str(replay.game_version).strip() or "-"
    player_count = int(run.player_count)
    mode_label = _replay_list_mode_label(
        game_mode_id=game_mode_id,
        player_count=player_count,
        quest_level=run.quest_level,
    )
    score_xp, kills = _replay_list_score_kills(
        replay=replay,
    )
    is_old = _is_version_older(replay_version=game_version, current_version=current_version)
    return (
        _ReplayListRow(
            replay=rel,
            mode=mode_label,
            game_mode_id=game_mode_id,
            game_version=game_version,
            ticks=str(ticks),
            duration=_fmt_replay_list_duration(ticks=ticks),
            score_xp=score_xp,
            kills=kills,
            modified=modified_text,
            modified_ts=float(modified_ts),
            old_version=bool(is_old),
        ),
        None,
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
    from ..runtime_resources_view import RuntimeResourcesView

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
        width = cfg.display.width
    if height is None:
        height = cfg.display.height
    console = create_console(base_dir, assets_dir=assets_dir)
    download_missing_paqs(assets_dir, console)

    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=False)
    view = ReplayPlaybackMode(ctx, replay_path=replay_path, config=cfg, console=console)
    title = f"Replay — {replay_path.name}"

    run_view(
        RuntimeResourcesView(view, assets_dir=assets_dir),
        width=width,
        height=height,
        title=title,
        fps=fps,
        hooks=RunViewHooks(should_close=view.should_close, consume_screenshot_request=view.consume_screenshot_request),
    )


@replay_app.command("list")
def cmd_replay_list(
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
    color: bool = typer.Option(
        True,
        "--color/--no-color",
        help="enable ANSI colors in table output (default: on)",
    ),
) -> None:
    """List replay files under base-dir/replays."""
    from rich import box
    from rich.console import Console
    from rich.table import Table

    from .. import __version__
    from ..replay import load_replay

    replays_dir = Path(base_dir) / "replays"
    replay_files = sorted(
        (path for path in replays_dir.rglob("*.crd") if path.is_file()),
        key=lambda path: str(path.relative_to(replays_dir)),
    )
    if not replay_files:
        typer.echo(f"no replay files found under {replays_dir}")
        return

    rows: list[_ReplayListRow] = []
    parse_errors: list[str] = []
    for replay_path in replay_files:
        row, parse_error = _build_replay_list_row(
            replay_path,
            replays_dir=replays_dir,
            load_replay_fn=load_replay,
            current_version=str(__version__),
        )
        rows.append(row)
        if parse_error:
            parse_errors.append(f"{row.replay}: {parse_error}")

    rows.sort(key=lambda row: (-float(row.modified_ts), str(row.replay)))

    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("replay")
    table.add_column("mode")
    table.add_column("version")
    table.add_column("ticks", justify="right")
    table.add_column("duration", justify="right")
    table.add_column("score", justify="right")
    table.add_column("kills", justify="right")
    table.add_column("modified", style="dim")
    for row in rows:
        mode_style = _replay_list_mode_style(row.game_mode_id)
        mode_cell = f"[{mode_style}]{row.mode}[/{mode_style}]"
        version_cell = row.game_version
        if row.mode in {"invalid", "error"}:
            mode_cell = f"[red]{row.mode}[/red]"
            version_cell = f"[red]{version_cell}[/red]"
        elif bool(row.old_version):
            version_cell = f"[yellow]{version_cell}[/yellow]"
        else:
            version_cell = f"[green]{version_cell}[/green]"
        table.add_row(
            row.replay,
            mode_cell,
            version_cell,
            row.ticks,
            row.duration,
            row.score_xp,
            row.kills,
            row.modified,
            style="dim" if bool(row.old_version) else "",
        )

    console = Console(force_terminal=bool(color), no_color=not bool(color), width=200)
    console.print(table)
    parsed_count = len(rows) - len(parse_errors)
    typer.echo(f"count={len(rows)} parsed={parsed_count} errors={len(parse_errors)}")
    typer.echo(f"replays_dir={replays_dir}")
    for parse_error in parse_errors:
        typer.echo(f"warning: {parse_error}")


@replay_app.command("verify")
def cmd_replay_verify(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
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
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Headlessly simulate a replay and check the result it recorded."""
    import hashlib

    from ..replay import ReplayCodecError, ReplayGameVersionError, decode_replay_payload, inflate_replay_payload
    from ..replay.driver.playback_driver import build_verify_playback_driver
    from ..replay.driver.setup import ReplayRunnerError
    from ..sim.run_result import run_result_mismatches

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    try:
        replay_payload = inflate_replay_payload(Path(replay_path).read_bytes())
        replay = decode_replay_payload(replay_payload)
        driver = build_verify_playback_driver(replay, max_ticks=max_ticks, trace_rng=trace_rng)
        result = driver.run()
    except (ReplayCodecError, ReplayGameVersionError, ReplayRunnerError) as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    mismatched_fields = run_result_mismatches(replay.result, result) if driver.complete else []
    status: Literal["ok", "result_mismatch", "partial"]
    if not driver.complete:
        status = "partial"
    elif mismatched_fields:
        status = "result_mismatch"
    else:
        status = "ok"
    payload = _ReplayVerifyPayload(
        schema_version=_REPLAY_VERIFY_SCHEMA_VERSION,
        status=status,
        replay=str(replay_path),
        payload_sha256=hashlib.sha256(replay_payload).hexdigest(),
        game_version=replay.game_version,
        ticks=len(replay.ticks),
        ticks_simulated=int(driver.tick_limit),
        result=result,
        recorded=replay.result,
        mismatched_fields=mismatched_fields,
    )
    payload_json = msgspec.json.encode(payload)

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)
        if output_format == "human":
            typer.echo(f"json_report={json_out}")

    if output_format == "json":
        typer.echo(payload_json.decode("utf-8"))
    else:
        player = result.players[0]
        message = (
            f"{status}: outcome={result.outcome} ticks={driver.tick_limit}/{len(replay.ticks)} "
            f"elapsed_ms={result.elapsed_ms} score_xp={player.experience} kills={result.kills} "
            f"rng_state={result.rng_state}"
        )
        if result.quest_final_ms is not None:
            message += f" quest_final_ms={result.quest_final_ms}"
        if mismatched_fields:
            message += f"; mismatches={','.join(mismatched_fields)}"
        typer.echo(message)

    if status == "result_mismatch":
        raise typer.Exit(code=_REPLAY_VERIFY_MISMATCH_EXIT_CODE)


@replay_app.command("info")
def cmd_replay_info(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    output_format: Literal["human", "json"] = typer.Option(
        "human",
        "--format",
        help="output format",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="optional JSON output path for replay info payload",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="include extra context events in addition to core gameplay events",
    ),
    player_index: int | None = typer.Option(
        None,
        "--player-index",
        help="optional player index filter (applies to player-specific events)",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Simulate a replay and emit a timeline of gameplay events."""
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay
    from ..replay.driver.playback_driver import build_verify_playback_driver
    from ..replay.driver.replay_info import collect_replay_info, event_counts_by_kind
    from ..replay.driver.setup import ReplayRunnerError

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    try:
        replay = load_replay(replay_bytes)
        result = collect_replay_info(
            build_verify_playback_driver(
                replay,
                max_ticks=max_ticks,
                warn_on_version_mismatch=True,
                trace_rng=False,
            ),
            player_index=player_index,
            include_extra_events=bool(verbose),
        )
    except (ReplayCodecError, ReplayGameVersionError, ReplayRunnerError) as exc:
        typer.echo(f"replay info failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    timeline_payload = [_replay_info_event_payload(event) for event in result.timeline]
    summary_payload = _replay_info_summary_payload(
        result,
        event_count=len(timeline_payload),
        event_counts_by_kind=event_counts_by_kind(result.timeline),
    )
    payload = _ReplayInfoPayload(
        schema_version=_REPLAY_INFO_SCHEMA_VERSION,
        status="ok",
        replay=str(replay_path),
        summary=summary_payload,
        timeline=timeline_payload,
    )
    payload_json = msgspec.json.encode(payload)

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)

    if output_format == "json":
        typer.echo(payload_json.decode("utf-8"))
        return

    typer.echo(
        "ok: "
        f"replay={replay_path} "
        f"mode={_replay_mode_label(summary_payload.game_mode_id)} "
        f"ticks={summary_payload.ticks_simulated} "
        f"elapsed_ms={summary_payload.elapsed_ms} "
        f"events={summary_payload.event_count}",
    )
    for event in timeline_payload:
        player_tag = f" [p{event.player_index}]" if event.player_index is not None else ""
        typer.echo(
            f"t={event.elapsed_s:.3f} tick={event.tick_index}{player_tag} {event.kind} {event.detail}",
        )

    tail = f"events={summary_payload.event_count}"
    if json_out is not None:
        tail += f" json_report={json_out}"
    typer.echo(tail)


@replay_app.command("benchmark")
def cmd_replay_benchmark(
    replay_file: Path = typer.Argument(
        ...,
        help="replay file path (.crd); if a filename is provided, also search base-dir/replays",
    ),
    runs: int | None = typer.Option(
        None,
        "--runs",
        min=1,
        help="number of measured benchmark runs (default: headless=5, render=1)",
    ),
    warmup_runs: int | None = typer.Option(
        None,
        "--warmup-runs",
        min=0,
        help="warmup runs before measured timing (default: headless=1, render=0)",
    ),
    mode: Literal["headless", "render"] = typer.Option(
        "headless",
        "--mode",
        help="benchmark mode: headless|render",
    ),
    rtx: bool = typer.Option(
        False,
        "--rtx",
        help="enable non-canonical RTX render mode (render mode only)",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
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
    render_telemetry: bool = typer.Option(
        False,
        "--render-telemetry",
        help="collect per-tick render telemetry (render mode only)",
    ),
    render_telemetry_out: Path | None = typer.Option(
        None,
        "--render-telemetry-out",
        help="optional output path for full render telemetry JSON (render mode only)",
    ),
    render_charts_out_dir: Path | None = typer.Option(
        None,
        "--render-charts-out-dir",
        help="optional output directory for render telemetry SVG charts (render mode only)",
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
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay
    from ..replay.driver.replay_benchmark import (
        ReplayBenchmarkError,
        run_replay_benchmark,
        run_replay_render_benchmark,
    )
    from ..replay.driver.setup import ReplayRunnerError

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    resolved_runs = runs if runs is not None else (1 if mode == "render" else 5)
    resolved_warmup_runs = warmup_runs if warmup_runs is not None else (0 if mode == "render" else 1)
    if mode != "render":
        if rtx:
            typer.echo("replay benchmark failed: --rtx is supported only with --mode render", err=True)
            raise typer.Exit(code=1)
        if render_telemetry:
            typer.echo("replay benchmark failed: --render-telemetry is supported only with --mode render", err=True)
            raise typer.Exit(code=1)
        if render_telemetry_out is not None:
            typer.echo("replay benchmark failed: --render-telemetry-out is supported only with --mode render", err=True)
            raise typer.Exit(code=1)
        if render_charts_out_dir is not None:
            typer.echo(
                "replay benchmark failed: --render-charts-out-dir is supported only with --mode render",
                err=True,
            )
            raise typer.Exit(code=1)

    try:
        replay = load_replay(replay_bytes)
        if mode == "render":
            benchmark = run_replay_render_benchmark(
                replay,
                replay_path=Path(replay_path),
                base_dir=Path(base_dir),
                runs=resolved_runs,
                warmup_runs=resolved_warmup_runs,
                max_ticks=max_ticks,
                trace_rng=trace_rng,
                profile=profile,
                profile_sort=profile_sort,
                top=top,
                profile_out=profile_out,
                render_telemetry=render_telemetry,
                render_telemetry_out=render_telemetry_out,
                render_charts_out_dir=render_charts_out_dir,
                rtx=rtx,
                show_progress=(output_format == "human"),
            )
        else:
            benchmark = run_replay_benchmark(
                replay,
                runs=resolved_runs,
                warmup_runs=resolved_warmup_runs,
                max_ticks=max_ticks,
                trace_rng=trace_rng,
                profile=profile,
                profile_sort=profile_sort,
                top=top,
                profile_out=profile_out,
                show_progress=(output_format == "human"),
            )
    except (ReplayCodecError, ReplayGameVersionError, ReplayBenchmarkError, ReplayRunnerError) as exc:
        typer.echo(f"replay benchmark failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    profile_payload = _replay_benchmark_profile_payload(benchmark.profile)

    render_telemetry_payload: _ReplayRenderTelemetryPayload | None = None
    if benchmark.render_telemetry is not None:
        telemetry_summary = benchmark.render_telemetry.summary
        render_telemetry_payload = _ReplayRenderTelemetryPayload(
            summary=_ReplayRenderTelemetrySummaryPayload(
                frame_ms=_benchmark_aggregate_payload(telemetry_summary.frame_ms),
                update_ms=_benchmark_aggregate_payload(telemetry_summary.update_ms),
                draw_ms=_benchmark_aggregate_payload(telemetry_summary.draw_ms),
                draw_calls_total=_benchmark_aggregate_payload(telemetry_summary.draw_calls_total),
                top_draw_ms_ticks=[
                    _render_telemetry_top_tick_payload(entry) for entry in telemetry_summary.top_draw_ms_ticks
                ],
                top_frame_ms_ticks=[
                    _render_telemetry_top_tick_payload(entry) for entry in telemetry_summary.top_frame_ms_ticks
                ],
                top_draw_calls_ticks=[
                    _render_telemetry_top_tick_payload(entry) for entry in telemetry_summary.top_draw_calls_ticks
                ],
            ),
            frames=[_render_telemetry_frame_payload(entry) for entry in benchmark.render_telemetry.frames],
            preview=[_render_telemetry_frame_payload(entry) for entry in benchmark.render_telemetry.preview],
            artifacts=_render_telemetry_artifacts_payload(benchmark.render_telemetry.artifacts),
        )

    payload = _ReplayBenchmarkPayload(
        schema_version=_REPLAY_BENCHMARK_SCHEMA_VERSION,
        status="ok",
        replay=str(replay_path),
        settings=_replay_benchmark_settings_payload(
            mode=mode,
            runs=resolved_runs,
            warmup_runs=resolved_warmup_runs,
            max_ticks=max_ticks,
            trace_rng=trace_rng,
            profile=profile,
            profile_sort=profile_sort,
            top=top,
            profile_out=profile_out,
            render_telemetry=render_telemetry,
            render_telemetry_out=render_telemetry_out,
            render_charts_out_dir=render_charts_out_dir,
        ),
        ticks=benchmark.ticks,
        run_result=benchmark.run_result,
        benchmark=_ReplayBenchmarkSummaryPayload(
            sample_count=len(benchmark.samples),
            samples=[_replay_benchmark_sample_payload(sample) for sample in benchmark.samples],
            wall_ms=_benchmark_aggregate_payload(benchmark.wall_ms),
            ticks_per_second=_benchmark_aggregate_payload(benchmark.ticks_per_second),
            realtime_x=_benchmark_aggregate_payload(benchmark.realtime_x),
        ),
        profile=profile_payload,
        render_telemetry=render_telemetry_payload,
    )
    payload_json = msgspec.json.encode(payload)

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)
        if output_format == "human":
            typer.echo(f"json_report={json_out}")

    if output_format == "json":
        typer.echo(payload_json.decode("utf-8"))
        return

    typer.echo(
        "ok: "
        f"mode={mode} "
        f"runs={len(benchmark.samples)} warmup_runs={resolved_warmup_runs} "
        f"ticks={benchmark.ticks} "
        f"wall_ms_p50={benchmark.wall_ms.p50:.3f} "
        f"tps_p50={benchmark.ticks_per_second.p50:.2f} "
        f"realtime_x_p50={benchmark.realtime_x.p50:.2f}",
    )
    typer.echo(_fmt_metric_agg("wall_ms", benchmark.wall_ms, digits=3))
    typer.echo(
        _fmt_metric_agg("throughput_tps", benchmark.ticks_per_second, digits=2)
        + " | "
        + _fmt_metric_agg("realtime_x", benchmark.realtime_x, digits=2),
    )
    if benchmark.render_telemetry is not None:
        telemetry = benchmark.render_telemetry
        typer.echo(
            "render_telemetry: "
            + _fmt_metric_agg("frame_ms", telemetry.summary.frame_ms, digits=3)
            + " | "
            + _fmt_metric_agg("update_ms", telemetry.summary.update_ms, digits=3)
            + " | "
            + _fmt_metric_agg("draw_ms", telemetry.summary.draw_ms, digits=3),
        )
        typer.echo(_fmt_metric_agg("draw_calls_total", telemetry.summary.draw_calls_total, digits=2))
        typer.echo("render_telemetry top_draw_ms_ticks:")
        if not telemetry.summary.top_draw_ms_ticks:
            typer.echo("  (none)")
        for row in telemetry.summary.top_draw_ms_ticks:
            typer.echo(f"  tick={int(row.tick_index)} frame={int(row.frame_index)} draw_ms={float(row.value):.3f}")
        artifacts = telemetry.artifacts
        if artifacts is not None:
            typer.echo("render_telemetry artifacts:")
            if artifacts.telemetry_json_path:
                typer.echo(f"  telemetry_json={artifacts.telemetry_json_path}")
            if artifacts.charts_dir:
                typer.echo(f"  charts_dir={artifacts.charts_dir}")
            if artifacts.frame_timing_svg:
                typer.echo(f"  frame_timing_svg={artifacts.frame_timing_svg}")
            if artifacts.draw_calls_svg:
                typer.echo(f"  draw_calls_svg={artifacts.draw_calls_svg}")
            if artifacts.pass_timing_stacked_svg:
                typer.echo(f"  pass_timing_stacked_svg={artifacts.pass_timing_stacked_svg}")
            if artifacts.report_md:
                typer.echo(f"  report_md={artifacts.report_md}")
    if benchmark.profile is None:
        return
    typer.echo(
        f"profile: sort={benchmark.profile.sort} source={benchmark.profile.source} top={benchmark.profile.top}",
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
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay
    from ..replay.driver.replay_render import ReplayRenderError, run_replay_render_video
    from ..replay.driver.setup import ReplayRunnerError

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    output_path = Path(out) if out is not None else _default_replay_render_output_path(replay_path)

    replay_bytes = Path(replay_path).read_bytes()
    progress_runtime: ReplayRenderProgress | None = None
    try:
        replay = load_replay(replay_bytes)
        total_ticks = len(replay.ticks)
        if max_ticks is not None:
            total_ticks = min(int(total_ticks), max(0, int(max_ticks)))
        progress_runtime = _replay_render_progress_runtime(
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
            trace_rng=bool(trace_rng),
            ffmpeg_bin=(Path(ffmpeg_bin) if ffmpeg_bin is not None else None),
            crf=int(crf),
            preset=preset,
            pixel_format=str(pixel_format),
            overwrite=bool(overwrite),
            mute_audio=not bool(audio),
            progress=progress_runtime,
        )
    except (ReplayCodecError, ReplayGameVersionError, ReplayRenderError, ReplayRunnerError) as exc:
        typer.echo(f"replay render failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if progress_runtime is not None:
            progress_runtime.close()

    message = (
        f"ok: output={render.output_path} "
        f"frames={render.frame_count} fps={render.fps} "
        f"resolution={render.width}x{render.height} "
        f"ticks={render.ticks} elapsed_ms={render.run_result.elapsed_ms} "
        f"score_xp={render.run_result.players[0].experience} kills={render.run_result.kills}"
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
    from ..dbg.checkpoint_diff import compare_checkpoints
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay
    from ..replay.checkpoints import (
        ReplayCheckpoint,
        ReplayCheckpointsError,
        default_checkpoints_path,
        load_checkpoints_file,
    )
    from ..replay.driver.playback_driver import PlaybackDriver, PlaybackWalkObserver, build_verify_playback_driver
    from ..replay.driver.setup import ReplayRunnerError
    from ..sim.hooks import TickResult
    from ..sim.world_state import WorldState

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)

    replay_bytes = Path(replay_path).read_bytes()
    try:
        replay = load_replay(replay_bytes)
    except ReplayCodecError as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if checkpoints_file is None:
        checkpoints_path = default_checkpoints_path(replay_path)
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

    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected.checkpoints}
    expected_by_tick = {int(ckpt.tick_index): ckpt for ckpt in expected.checkpoints}
    actual: list[ReplayCheckpoint] = []

    class _CheckpointMismatchStop(Exception):
        def __init__(self, diff: object) -> None:
            self.diff = diff

    class _CheckpointVerifyObserver(PlaybackWalkObserver):
        driver: PlaybackDriver
        checkpoint_ticks: set[int]
        actual: list[ReplayCheckpoint]

        def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
            _ = world
            tick_index = int(tick_result.source_tick.tick_index)
            if tick_index in self.checkpoint_ticks:
                checkpoint = self.driver.build_checkpoint(tick_result=tick_result)
                self.actual.append(checkpoint)
                tick_diff = compare_checkpoints(
                    [expected_by_tick[tick_index]],
                    [checkpoint],
                )
                if not tick_diff.ok:
                    raise _CheckpointMismatchStop(tick_diff)

    try:
        driver = build_verify_playback_driver(
            replay,
            max_ticks=max_ticks,
            trace_rng=bool(trace_rng),
        )

        result = driver.run(
            observer=_CheckpointVerifyObserver(
                driver=driver,
                checkpoint_ticks=checkpoint_ticks,
                actual=actual,
            ),
        )
    except _CheckpointMismatchStop as exc:
        _render_checkpoint_diff_failure(cast("ReplayDiffResult", exc.diff))
    except (ReplayGameVersionError, ReplayRunnerError) as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    diff = compare_checkpoints(expected.checkpoints, actual)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = (
        f"ok: {len(expected.checkpoints)} checkpoints match; ticks={driver.tick_limit} "
        f"score_xp={result.players[0].experience} kills={result.kills}"
    )
    typer.echo(message)


@replay_app.command("diff-checkpoints")
def cmd_replay_diff_checkpoints(
    expected_file: Path = typer.Argument(..., help="expected checkpoints sidecar (.crd.chk)"),
    actual_file: Path = typer.Argument(..., help="actual checkpoints sidecar (.crd.chk)"),
) -> None:
    """Compare two checkpoint sidecars and report the first divergence."""
    from ..dbg.checkpoint_diff import compare_checkpoints
    from ..replay.checkpoints import load_checkpoints_file

    expected = load_checkpoints_file(Path(expected_file))
    actual = load_checkpoints_file(Path(actual_file))
    diff = compare_checkpoints(expected.checkpoints, actual.checkpoints)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = f"ok: {len(expected.checkpoints)} checkpoints match"
    typer.echo(message)
