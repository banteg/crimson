from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import msgspec
import typer

from ..game_modes import GameMode
from ..paths import default_runtime_dir
from ..quests.level import QuestLevel

if TYPE_CHECKING:
    from ..replay import Replay
    from ..replay.checkpoint_diff import ReplayDiffResult
    from ..replay.driver.replay_benchmark import BenchmarkAggregate

_REPLAY_VERIFY_SCHEMA_VERSION = 4
_REPLAY_INFO_SCHEMA_VERSION = 2
_REPLAY_BENCHMARK_SCHEMA_VERSION = 4
_REPLAY_VERIFY_MISMATCH_EXIT_CODE = 3


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


def _require_replay_path(replay_file: Path, *, base_dir: Path) -> Path:
    """The replay file `replay_file` names, or exit reporting where it was looked for."""

    replay_path, tried = _resolve_replay_path(replay_file, base_dir=base_dir)
    if not replay_path.is_file():
        message = f"replay file not found: {tried[0]}"
        if len(tried) > 1:
            message += f" (also tried: {tried[1]})"
        typer.echo(message, err=True)
        raise typer.Exit(code=1)
    return replay_path


def _default_replay_render_output_path(replay_path: Path) -> Path:
    return Path(replay_path).with_suffix(".render.mp4")


def _render_checkpoint_diff_failure(diff: ReplayDiffResult, *, actual_rng_callers: Sequence[int] | None = None) -> None:
    """Report the first divergence; `actual_rng_callers` are the diverging tick's draws when the verifier ran it."""
    from ..replay.checkpoint_diff import checkpoint_deepdiff
    from ..replay.rng_call_order import caller_names

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
    typer.echo(
        f"  rng_callers_crc32 expected=0x{exp.rng_callers_crc32:08x} actual=0x{act.rng_callers_crc32:08x}",
        err=True,
    )
    if exp.rng_callers_crc32 != act.rng_callers_crc32 and actual_rng_callers is not None:
        typer.echo(
            f"  rng call order diverged at tick={int(failure.tick_index)}: {len(actual_rng_callers)} draws "
            f"{caller_names(actual_rng_callers)}",
            err=True,
        )
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
    return game_mode_id.name.lower()


def _path_text(path: Path | None) -> str | None:
    return None if path is None else str(path)


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
    from grim.view import ViewContext

    from ..modes.replay_playback_mode import ReplayPlaybackMode
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay_file, warn_on_game_version_mismatch
    from ..runtime_boot import boot_runtime
    from ..runtime_resources_view import RuntimeResourcesView

    if assets_dir is None:
        assets_dir = base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    replay_path = _require_replay_path(replay_file, base_dir=base_dir)
    try:
        replay = load_replay_file(replay_path)
        warn_on_game_version_mismatch(replay, action="playback")
    except (ReplayCodecError, ReplayGameVersionError) as exc:
        typer.echo(f"replay playback failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    boot = boot_runtime(base_dir, assets_dir, width=width, height=height)

    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=False)
    view = ReplayPlaybackMode(ctx, replay=replay, config=boot.config, console=boot.console)
    title = f"Replay — {replay_path.name}"

    run_view(
        RuntimeResourcesView(view, assets_dir=assets_dir),
        width=boot.width,
        height=boot.height,
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
    from ..replay.ranked import unranked_reasons
    from ..sim.run_result import run_result_mismatches

    replay_path = _require_replay_path(replay_file, base_dir=base_dir)

    try:
        replay_payload = inflate_replay_payload(Path(replay_path).read_bytes())
        replay = decode_replay_payload(replay_payload)
        driver = build_verify_playback_driver(replay, max_ticks=max_ticks)
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
    unranked = unranked_reasons(replay.run)
    payload_json = msgspec.json.encode({
        "schema_version": _REPLAY_VERIFY_SCHEMA_VERSION,
        "status": status,
        "replay": str(replay_path),
        "payload_sha256": hashlib.sha256(replay_payload).hexdigest(),
        "game_version": replay.game_version,
        "ticks": len(replay.ticks),
        "ticks_simulated": int(driver.tick_limit),
        "result": result,
        "recorded": replay.result,
        "mismatched_fields": mismatched_fields,
        # Whether the run was played in the leaderboard's ranked profile.
        "ranked": not unranked,
        "unranked_reasons": unranked,
    })

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
        if unranked:
            message += f"; unranked={','.join(unranked)}"
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

    replay_path = _require_replay_path(replay_file, base_dir=base_dir)

    replay_bytes = Path(replay_path).read_bytes()
    try:
        replay = load_replay(replay_bytes)
        result = collect_replay_info(
            build_verify_playback_driver(
                replay,
                max_ticks=max_ticks,
                warn_on_version_mismatch=True,
            ),
            player_index=player_index,
            include_extra_events=bool(verbose),
        )
    except (ReplayCodecError, ReplayGameVersionError, ReplayRunnerError) as exc:
        typer.echo(f"replay info failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload_json = msgspec.json.encode({
        "schema_version": _REPLAY_INFO_SCHEMA_VERSION,
        "status": "ok",
        "replay": str(replay_path),
        "summary": {
            "game_mode_id": result.game_mode_id,
            "tick_rate": result.tick_rate,
            "ticks_simulated": result.ticks_simulated,
            "elapsed_ms": result.elapsed_ms,
            "player_count": result.player_count,
            "event_count": len(result.timeline),
            "event_counts_by_kind": event_counts_by_kind(result.timeline),
        },
        "timeline": result.timeline,
    })

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_bytes(payload_json)

    if output_format == "json":
        typer.echo(payload_json.decode("utf-8"))
        return

    typer.echo(
        "ok: "
        f"replay={replay_path} "
        f"mode={_replay_mode_label(result.game_mode_id)} "
        f"ticks={result.ticks_simulated} "
        f"elapsed_ms={result.elapsed_ms} "
        f"events={len(result.timeline)}",
    )
    for event in result.timeline:
        player_tag = f" [p{event.player_index}]" if event.player_index is not None else ""
        typer.echo(
            f"t={event.elapsed_s:.3f} tick={event.tick_index}{player_tag} {event.kind} {event.detail}",
        )

    tail = f"events={len(result.timeline)}"
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

    replay_path = _require_replay_path(replay_file, base_dir=base_dir)

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
                profile=profile,
                profile_sort=profile_sort,
                top=top,
                profile_out=profile_out,
                show_progress=(output_format == "human"),
            )
    except (ReplayCodecError, ReplayGameVersionError, ReplayBenchmarkError, ReplayRunnerError) as exc:
        typer.echo(f"replay benchmark failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload_json = msgspec.json.encode({
        "schema_version": _REPLAY_BENCHMARK_SCHEMA_VERSION,
        "status": "ok",
        "replay": str(replay_path),
        "settings": {
            "mode": mode,
            "runs": resolved_runs,
            "warmup_runs": resolved_warmup_runs,
            "max_ticks": max_ticks,
            "profile": profile,
            "profile_sort": profile_sort,
            "top": top,
            "profile_out": _path_text(profile_out),
            "render_telemetry": render_telemetry,
            "render_telemetry_out": _path_text(render_telemetry_out),
            "render_charts_out_dir": _path_text(render_charts_out_dir),
        },
        "ticks": benchmark.ticks,
        "run_result": benchmark.run_result,
        "benchmark": {
            "sample_count": len(benchmark.samples),
            "samples": benchmark.samples,
            "wall_ms": benchmark.wall_ms,
            "ticks_per_second": benchmark.ticks_per_second,
            "realtime_x": benchmark.realtime_x,
        },
        "profile": benchmark.profile,
        "render_telemetry": benchmark.render_telemetry,
    })

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

    replay_path = _require_replay_path(replay_file, base_dir=base_dir)

    output_path = Path(out) if out is not None else _default_replay_render_output_path(replay_path)

    replay_bytes = Path(replay_path).read_bytes()
    try:
        replay = load_replay(replay_bytes)
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
            ffmpeg_bin=(Path(ffmpeg_bin) if ffmpeg_bin is not None else None),
            crf=int(crf),
            preset=preset,
            pixel_format=str(pixel_format),
            overwrite=bool(overwrite),
            mute_audio=not bool(audio),
            show_progress=True,
        )
    except (ReplayCodecError, ReplayGameVersionError, ReplayRenderError, ReplayRunnerError) as exc:
        typer.echo(f"replay render failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

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
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Verify a replay by comparing headless checkpoints with a sidecar file."""
    from ..replay import ReplayCodecError, ReplayGameVersionError, load_replay
    from ..replay.checkpoint_diff import compare_checkpoints
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

    replay_path = _require_replay_path(replay_file, base_dir=base_dir)

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
        def __init__(self, diff: object, rng_callers: list[int]) -> None:
            self.diff = diff
            self.rng_callers = rng_callers

    class _CheckpointVerifyObserver(PlaybackWalkObserver):
        driver: PlaybackDriver
        checkpoint_ticks: set[int]
        actual: list[ReplayCheckpoint]

        def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
            _ = world
            tick_index = int(tick_result.tick_index)
            if tick_index in self.checkpoint_ticks:
                checkpoint = self.driver.build_checkpoint(tick_result=tick_result)
                self.actual.append(checkpoint)
                tick_diff = compare_checkpoints(
                    [expected_by_tick[tick_index]],
                    [checkpoint],
                )
                if not tick_diff.ok:
                    raise _CheckpointMismatchStop(tick_diff, list(self.driver.rng_call_order.callers))

    try:
        driver = build_verify_playback_driver(replay, max_ticks=max_ticks)

        result = driver.run(
            observer=_CheckpointVerifyObserver(
                driver=driver,
                checkpoint_ticks=checkpoint_ticks,
                actual=actual,
            ),
        )
    except _CheckpointMismatchStop as exc:
        _render_checkpoint_diff_failure(cast("ReplayDiffResult", exc.diff), actual_rng_callers=exc.rng_callers)
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
    from ..replay.checkpoint_diff import compare_checkpoints
    from ..replay.checkpoints import load_checkpoints_file

    expected = load_checkpoints_file(Path(expected_file))
    actual = load_checkpoints_file(Path(actual_file))
    diff = compare_checkpoints(expected.checkpoints, actual.checkpoints)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = f"ok: {len(expected.checkpoints)} checkpoints match"
    typer.echo(message)
