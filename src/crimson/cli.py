from __future__ import annotations

import inspect
import io
import ipaddress
import json
import os
import random
import re
import sys
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import msgspec
import typer
from PIL import Image
from tqdm import tqdm

from grim import jaz, paq
from grim.geom import Vec2
from grim.rand import Crand

from .creatures.spawn import SpawnEnv, build_spawn_plan, spawn_id_label
from .game_modes import GameMode
from .paths import default_runtime_dir
from .quests import all_quests
from .quests.types import QuestContext, QuestDefinition, SpawnEntry

app = typer.Typer(add_completion=False)
replay_app = typer.Typer(add_completion=False)
original_app = typer.Typer(add_completion=False)
lan_app = typer.Typer(add_completion=False)
net_app = typer.Typer(add_completion=False)
relay_app = typer.Typer(add_completion=False)
app.add_typer(replay_app, name="replay")
app.add_typer(original_app, name="original")
app.add_typer(lan_app, name="lan")
app.add_typer(net_app, name="net")
app.add_typer(relay_app, name="relay")

_QUEST_DEFS: dict[str, QuestDefinition] = {quest.level: quest for quest in all_quests()}
_QUEST_BUILDERS = {level: quest.builder for level, quest in _QUEST_DEFS.items()}
_QUEST_TITLES = {level: quest.title for level, quest in _QUEST_DEFS.items()}

_SEP_RE = re.compile(r"[\\/]+")
_REPLAY_VERIFY_SCHEMA_VERSION = 1
_REPLAY_BENCHMARK_SCHEMA_VERSION = 1
_REPLAY_VERIFY_SCORE_MISMATCH_EXIT_CODE = 3
_SessionMode = Literal["survival", "rush", "quests"]
_ParsedNetcodeMode = Literal["rollback", "lockstep_legacy"]


class _ProgressBarLike(Protocol):
    total: int

    def update(self, value: int) -> None: ...

    def set_postfix(self, *, refresh: bool = True, **kwargs: Any) -> None: ...

    def close(self) -> None: ...


def _view_run_hooks(view: object):
    from grim.app import RunViewHooks

    def should_close() -> bool:
        should_close_fn = getattr(view, "should_close", None)
        if callable(should_close_fn):
            return bool(should_close_fn())
        close_requested = getattr(view, "close_requested", False)
        if isinstance(close_requested, bool):
            return close_requested
        return False

    def consume_screenshot_request() -> bool:
        consume_fn = getattr(view, "consume_screenshot_request", None)
        if callable(consume_fn):
            return bool(consume_fn())
        return False

    return RunViewHooks(
        should_close=should_close,
        consume_screenshot_request=consume_screenshot_request,
    )


def _is_loopback_host(host: str) -> bool:
    normalized = str(host).strip().strip("[]").lower()
    if not normalized:
        return False
    if normalized == "localhost":
        return True
    try:
        return bool(ipaddress.ip_address(normalized).is_loopback)
    except ValueError:
        return False


def _parse_session_mode(mode: str) -> _SessionMode:
    mode_name = str(mode).strip().lower()
    if mode_name == "survival":
        return "survival"
    if mode_name == "rush":
        return "rush"
    if mode_name == "quests":
        return "quests"
    raise typer.BadParameter(
        f"unsupported mode {mode!r}; expected one of: survival, rush, quests",
        param_hint="--mode",
    )


def _parse_netcode_mode(raw: str) -> _ParsedNetcodeMode:
    value = str(raw).strip().lower()
    if value in {"rollback", "rb"}:
        return "rollback"
    if value in {"lockstep", "lockstep_legacy", "legacy"}:
        return "lockstep_legacy"
    raise typer.BadParameter(
        f"unsupported netcode {raw!r}; expected rollback|lockstep",
        param_hint="--netcode",
    )


def _safe_relpath(name: str) -> Path:
    parts = [p for p in _SEP_RE.split(name) if p]
    if not parts:
        raise ValueError("empty entry name")
    for part in parts:
        if part in (".", ".."):
            raise ValueError(f"unsafe path part: {part!r}")
    return Path(*parts)


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
) -> tuple[object | None, object | None]:
    if int(total_ticks) <= 0:
        return None, None

    video_bar = cast(
        _ProgressBarLike,
        tqdm(
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
            tqdm(
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


def _extract_one(paq_path: Path, assets_root: Path) -> int:
    out_root = assets_root / paq_path.stem
    out_root.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, data in paq.iter_entries(paq_path):
        rel = _safe_relpath(name)
        dest = out_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        suffix = dest.suffix.lower()
        if suffix == ".jaz":
            jaz_image = jaz.decode_jaz_bytes(data)
            base = dest.with_suffix("")
            jaz_image.composite_image().save(base.with_suffix(".png"))
        else:
            if suffix == ".tga":
                img = Image.open(io.BytesIO(data))
                img.save(dest.with_suffix(".png"))
            else:
                dest.write_bytes(data)
        count += 1
    return count


@app.command("extract")
def cmd_extract(game_dir: Path, assets_dir: Path) -> None:
    """Extract all .paq files into a flat asset directory."""
    if not game_dir.is_dir():
        typer.echo(f"game dir not found: {game_dir}", err=True)
        raise typer.Exit(code=1)
    assets_dir.mkdir(parents=True, exist_ok=True)
    paqs = sorted(game_dir.rglob("*.paq"))
    if not paqs:
        typer.echo(f"no .paq files under {game_dir}", err=True)
        raise typer.Exit(code=1)
    total = 0
    for paq_path in paqs:
        total += _extract_one(paq_path, assets_dir)
    typer.echo(f"extracted {total} files")


def _call_builder(builder, ctx: QuestContext, rng: random.Random | None) -> list[SpawnEntry]:
    params = inspect.signature(builder).parameters
    if "rng" in params:
        return builder(ctx, rng=rng)
    return builder(ctx)


def _format_entry(idx: int, entry: SpawnEntry, *, plan_info: tuple[int, int] | None) -> str:
    creature = spawn_id_label(entry.spawn_id)
    plan_text = ""
    if plan_info is not None:
        creatures_per_spawn, spawn_slots_per_spawn = plan_info
        alloc = entry.count * creatures_per_spawn
        plan_text = f"  alloc={alloc:3d} (x{creatures_per_spawn:2d})  slots={spawn_slots_per_spawn}"
    return (
        f"{idx:02d}  t={entry.trigger_ms:5d}  "
        f"id=0x{entry.spawn_id:02x} ({entry.spawn_id:2d})  "
        f"creature={creature:10s}  "
        f"count={entry.count:2d}  "
        f"x={entry.pos.x:7.1f}  y={entry.pos.y:7.1f}  heading={entry.heading:7.3f}{plan_text}"
    )


def _format_id(value: int | None) -> str:
    if value is None:
        return "none"
    return f"0x{value:02x} ({value})"


def _format_id_list(values: tuple[int, ...] | None) -> str:
    if not values:
        return "none"
    return "[" + ", ".join(_format_id(value) for value in values) + "]"


def _format_meta(quest: QuestDefinition) -> list[str]:
    builder_addr = f"0x{quest.builder_address:08x}" if quest.builder_address is not None else "unknown"
    terrain_ids = _format_id_list(quest.terrain_ids)
    return [
        f"time_limit_ms={quest.time_limit_ms}",
        f"start_weapon_id={quest.start_weapon_id}",
        f"unlock_perk_id={_format_id(quest.unlock_perk_id)}",
        f"unlock_weapon_id={_format_id(quest.unlock_weapon_id)}",
        f"builder_address={builder_addr}",
        f"terrain_ids={terrain_ids}",
    ]


@app.command("quests")
def cmd_quests(
    level: str = typer.Argument(..., help="quest level, e.g. 1.1"),
    width: int = typer.Option(1024, help="terrain width"),
    height: int = typer.Option(1024, help="terrain height"),
    player_count: int = typer.Option(1, help="player count"),
    seed: int | None = typer.Option(None, help="seed for randomized quests"),
    sort: bool = typer.Option(False, help="sort output by trigger time"),
    show_plan: bool = typer.Option(False, help="include spawn-plan allocation summary"),
) -> None:
    """Print quest spawn scripts for a given level."""
    quest = _QUEST_DEFS.get(level)
    if quest is None:
        available = ", ".join(sorted(_QUEST_BUILDERS))
        typer.echo(f"unknown level {level!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    builder = quest.builder
    title = quest.title
    ctx = QuestContext(width=width, height=height, player_count=player_count)
    rng = random.Random(seed) if seed is not None else random.Random()
    entries = _call_builder(builder, ctx, rng)
    if sort:
        entries = sorted(entries, key=lambda e: (e.trigger_ms, e.spawn_id, e.x, e.y))
    typer.echo(f"Quest {level} {title} ({len(entries)} entries)")
    typer.echo("Meta: " + "; ".join(_format_meta(quest)))

    plan_cache: dict[int, tuple[int, int]] = {}
    if show_plan:
        env = SpawnEnv(
            terrain_width=float(width),
            terrain_height=float(height),
            demo_mode_active=True,
            hardcore=False,
            difficulty_level=0,
        )
        for entry in entries:
            if entry.spawn_id in plan_cache:
                continue
            plan = build_spawn_plan(entry.spawn_id, Vec2(512.0, 512.0), 0.0, Crand(0), env)
            plan_cache[entry.spawn_id] = (len(plan.creatures), len(plan.spawn_slots))
        total_alloc = sum(entry.count * plan_cache[entry.spawn_id][0] for entry in entries)
        total_slots = sum(entry.count * plan_cache[entry.spawn_id][1] for entry in entries)
        typer.echo(f"Plan: total_alloc={total_alloc} total_spawn_slots={total_slots}")

    for idx, entry in enumerate(entries, start=1):
        typer.echo(_format_entry(idx, entry, plan_info=plan_cache.get(entry.spawn_id)))


@app.command("view")
def cmd_view(
    name: str = typer.Argument(..., help="view name (e.g. empty)"),
    width: int = typer.Option(1024, help="window width"),
    height: int = typer.Option(768, help="window height"),
    fps: int = typer.Option(60, help="target fps"),
    dump_shader_debug_views: bool = typer.Option(
        False,
        "--dump-shader-debug-views",
        help="lighting-debug only: run autodiag and dump screenshots for each shader debug mode",
    ),
    dump_shader_debug_frames: int = typer.Option(
        399,
        "--dump-shader-debug-frames",
        min=30,
        help="lighting-debug only: total autodiag frames used when --dump-shader-debug-views is set",
    ),
    autotune_shadow_defaults: bool = typer.Option(
        False,
        "--autotune-shadow-defaults",
        help="lighting-debug only: run an automated quality/perf sweep and print the best tuning preset",
    ),
    autotune_shadow_frames: int = typer.Option(
        96,
        "--autotune-shadow-frames",
        min=12,
        help="lighting-debug only: sampled frames per preset when --autotune-shadow-defaults is set",
    ),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    assets_dir: Path = typer.Option(Path("artifacts") / "assets", help="assets root (default: ./artifacts/assets)"),
) -> None:
    """Launch a Raylib debug view."""
    from grim.app import run_view
    from grim.view import ViewContext

    from .views import all_views, view_by_name

    view_def = view_by_name(name)
    if view_def is None:
        available = ", ".join(view.name for view in all_views())
        typer.echo(f"unknown view {name!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    if dump_shader_debug_views and autotune_shadow_defaults:
        typer.echo(
            "--dump-shader-debug-views and --autotune-shadow-defaults cannot be used together",
            err=True,
        )
        raise typer.Exit(code=1)
    if dump_shader_debug_views:
        if str(name) != "lighting-debug":
            typer.echo("--dump-shader-debug-views is only supported for view 'lighting-debug'", err=True)
            raise typer.Exit(code=1)
        os.environ["CRIMSON_LIGHTING_DEBUG_DUMP_ALL_MODES"] = "1"
        os.environ["CRIMSON_LIGHTING_DEBUG_AUTODIAG"] = str(int(dump_shader_debug_frames))
    if autotune_shadow_defaults:
        if str(name) != "lighting-debug":
            typer.echo("--autotune-shadow-defaults is only supported for view 'lighting-debug'", err=True)
            raise typer.Exit(code=1)
        os.environ["CRIMSON_LIGHTING_DEBUG_AUTO_TUNE"] = str(int(autotune_shadow_frames))
    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=bool(preserve_bugs))
    params = inspect.signature(view_def.factory).parameters
    if "ctx" in params:
        view = view_def.factory(ctx=ctx)
    else:
        view = view_def.factory()
    title = f"{view_def.title} — Crimsonland"
    run_view(
        view,
        width=width,
        height=height,
        title=title,
        fps=fps,
        hooks=_view_run_hooks(view),
    )


def _run_game_with_pending_session(
    *,
    pending,
    base_dir: Path,
    assets_dir: Path | None,
    width: int | None,
    height: int | None,
    fps: int,
    debug: bool,
) -> None:
    from .game import GameConfig, run_game

    run_game(
        GameConfig(
            base_dir=base_dir,
            assets_dir=assets_dir,
            width=width,
            height=height,
            fps=fps,
            debug=bool(debug),
            preserve_bugs=False,
            pending_net_session=pending,
            pending_lan_session=pending,
        ),
    )


@relay_app.command("serve")
def cmd_relay_serve(
    bind: str = typer.Option("0.0.0.0", "--bind", help="relay bind address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="relay UDP port"),
    tick_ms: int = typer.Option(8, "--tick-ms", min=1, max=1000, help="relay update tick interval"),
    log_level: str = typer.Option("debug", "--log-level", help="relay log level (debug|info|warning|error)"),
    log_file: Path | None = typer.Option(
        None,
        "--log-file",
        help="relay log file path (default: runtime-dir/logs/relay/relay-<pid>-<ts>.log)",
    ),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for relay logs (default: per-user OS data dir)",
    ),
) -> None:
    """Serve the in-repo UDP relay."""
    from .logging import configure_component_logging, default_component_log_path
    from .net.relay_service import RelayServer, RelayServerConfig

    resolved_log_file = (
        Path(log_file).expanduser()
        if log_file is not None
        else default_component_log_path(base_dir=base_dir, component="relay")
    )
    try:
        configured_log_file = configure_component_logging(
            logger_name="crimson.relay",
            component="relay",
            log_file=resolved_log_file,
            level=log_level,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--log-level") from exc
    typer.echo(f"relay logs -> {configured_log_file}")

    server = RelayServer(
        RelayServerConfig(
            bind_host=str(bind).strip() or "0.0.0.0",
            bind_port=int(port),
        ),
    )
    server.serve_forever(tick_ms=max(1, int(tick_ms)))


@net_app.command("host")
def cmd_net_host(
    mode: str = typer.Option(..., "--mode", help="survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor (required for quests mode)"),
    players: int = typer.Option(..., "--players", min=1, max=4, help="player count (1..4)"),
    bind: str = typer.Option("0.0.0.0", "--bind", help="local bind address"),
    relay_host: str = typer.Option("127.0.0.1", "--relay-host", help="relay host or IP"),
    relay_port: int = typer.Option(31993, "--relay-port", min=1, max=65535, help="relay UDP port"),
    room_code: str = typer.Option("", "--room-code", help="optional room code override"),
    netcode: str = typer.Option("rollback", "--netcode", help="rollback|lockstep"),
    rollback_max_ticks: int = typer.Option(8, "--rollback-max-ticks", min=1, max=64, help="rollback cap ticks"),
    reconnect_timeout_ms: int = typer.Option(
        15_000,
        "--reconnect-timeout-ms",
        min=1_000,
        max=120_000,
        help="reconnect timeout in milliseconds",
    ),
    input_delay_ticks: int = typer.Option(1, "--input-delay-ticks", min=0, max=8, help="local input delay"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
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
    """Host a network session (rollback default)."""
    from .game.types import LanSessionConfig, PendingLanSession
    from .quests.types import parse_level

    resolved_mode = _parse_session_mode(mode)
    normalized_quest_level = str(quest_level).strip()
    if resolved_mode == "quests":
        if not normalized_quest_level:
            raise typer.BadParameter("quest level is required for quests mode", param_hint="--quest-level")
        try:
            parse_level(normalized_quest_level)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--quest-level") from exc
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode=resolved_mode,
            player_count=int(players),
            quest_level=normalized_quest_level,
            bind_host=str(bind).strip() or "0.0.0.0",
            relay_host=str(relay_host).strip() or "127.0.0.1",
            relay_port=int(relay_port),
            room_code=str(room_code).strip().upper(),
            host_ip=str(relay_host).strip() or "127.0.0.1",
            port=int(relay_port),
            netcode_mode=_parse_netcode_mode(netcode),
            rollback_max_ticks=int(rollback_max_ticks),
            reconnect_timeout_ms=int(reconnect_timeout_ms),
            input_delay_ticks=int(input_delay_ticks),
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
    )


@net_app.command("join")
def cmd_net_join(
    code: str = typer.Option(..., "--code", help="invite room code"),
    mode: str = typer.Option("survival", "--mode", help="expected mode: survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor"),
    relay_host: str = typer.Option("127.0.0.1", "--relay-host", help="relay host or IP"),
    relay_port: int = typer.Option(31993, "--relay-port", min=1, max=65535, help="relay UDP port"),
    netcode: str = typer.Option("rollback", "--netcode", help="rollback|lockstep"),
    rollback_max_ticks: int = typer.Option(8, "--rollback-max-ticks", min=1, max=64, help="rollback cap ticks"),
    reconnect_timeout_ms: int = typer.Option(
        15_000,
        "--reconnect-timeout-ms",
        min=1_000,
        max=120_000,
        help="reconnect timeout in milliseconds",
    ),
    input_delay_ticks: int = typer.Option(1, "--input-delay-ticks", min=0, max=8, help="local input delay"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
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
    """Join a network session via invite room code."""
    from .game.types import LanSessionConfig, PendingLanSession

    room_code = str(code).strip().upper()
    if not room_code:
        raise typer.BadParameter("room code is required", param_hint="--code")
    pending = PendingLanSession(
        role="join",
        config=LanSessionConfig(
            mode=_parse_session_mode(mode),
            player_count=1,
            quest_level=str(quest_level).strip(),
            bind_host="0.0.0.0",
            relay_host=str(relay_host).strip() or "127.0.0.1",
            relay_port=int(relay_port),
            room_code=room_code,
            host_ip=str(relay_host).strip() or "127.0.0.1",
            port=int(relay_port),
            netcode_mode=_parse_netcode_mode(netcode),
            rollback_max_ticks=int(rollback_max_ticks),
            reconnect_timeout_ms=int(reconnect_timeout_ms),
            input_delay_ticks=int(input_delay_ticks),
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
    )


@lan_app.command("host")
def cmd_lan_host(
    mode: str = typer.Option(..., "--mode", help="survival|rush|quests"),
    quest_level: str = typer.Option("", "--quest-level", help="quest level major.minor (required for quests mode)"),
    players: int = typer.Option(..., "--players", min=1, max=4, help="player count (1..4)"),
    bind: str = typer.Option("0.0.0.0", "--bind", help="host bind address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="host UDP port"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
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
    """Deprecated wrapper for `net host`."""
    from .game.types import LanSessionConfig, PendingLanSession
    from .quests.types import parse_level

    typer.echo("warning: `crimson lan host` is deprecated; use `crimson net host`.", err=True)
    resolved_mode = _parse_session_mode(mode)
    normalized_quest_level = str(quest_level).strip()
    if resolved_mode == "quests":
        if not normalized_quest_level:
            raise typer.BadParameter("quest level is required for quests mode", param_hint="--quest-level")
        try:
            parse_level(normalized_quest_level)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--quest-level") from exc
    pending = PendingLanSession(
        role="host",
        config=LanSessionConfig(
            mode=resolved_mode,
            player_count=int(players),
            quest_level=normalized_quest_level,
            bind_host=str(bind).strip() or "0.0.0.0",
            relay_host=str(bind).strip() or "127.0.0.1",
            relay_port=int(port),
            room_code="",
            host_ip="",
            port=int(port),
            netcode_mode="rollback",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
    )


@lan_app.command("join")
def cmd_lan_join(
    host: str = typer.Option(..., "--host", help="host IP address"),
    port: int = typer.Option(31993, "--port", min=1, max=65535, help="host UDP port"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
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
    """Deprecated wrapper for `net join`."""
    from .game.types import LanSessionConfig, PendingLanSession

    typer.echo("warning: `crimson lan join` is deprecated; use `crimson net join --code`.", err=True)
    host_ip = str(host).strip()
    if not host_ip:
        raise typer.BadParameter("host address is required", param_hint="--host")
    pending = PendingLanSession(
        role="join",
        config=LanSessionConfig(
            mode="survival",
            player_count=1,
            quest_level="",
            bind_host="0.0.0.0",
            relay_host=host_ip,
            relay_port=int(port),
            room_code="",
            host_ip=host_ip,
            port=int(port),
            netcode_mode="lockstep_legacy",
            rollback_max_ticks=8,
            reconnect_timeout_ms=15_000,
            input_delay_ticks=1,
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    _run_game_with_pending_session(
        pending=pending,
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        debug=bool(debug),
    )


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

    from .assets_fetch import download_missing_paqs
    from .modes.replay_playback_mode import ReplayPlaybackMode

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

    from .replay import ReplayCodecError, load_replay
    from .sim.driver.replay_runner import ReplayRunnerError, run_replay

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

    from .replay import ReplayCodecError, load_replay
    from .sim.driver.replay_benchmark import (
        ReplayBenchmarkError,
        run_replay_benchmark,
        run_replay_render_benchmark,
    )
    from .sim.driver.replay_runner import ReplayRunnerError

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
    from .replay import ReplayCodecError, load_replay
    from .sim.driver.replay_render import ReplayRenderError, run_replay_render_video
    from .sim.driver.replay_runner import ReplayRunnerError

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

    from .original.diff import compare_checkpoints
    from .replay import ReplayCodecError, load_replay
    from .replay.checkpoints import (
        ReplayCheckpointsError,
        default_checkpoints_path,
        legacy_checkpoints_path,
        load_checkpoints_file,
    )
    from .sim.driver.replay_runner import ReplayRunnerError, run_replay

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
    from .original.diff import compare_checkpoints
    from .replay.checkpoints import load_checkpoints_file

    expected = load_checkpoints_file(Path(expected_file))
    actual = load_checkpoints_file(Path(actual_file))
    diff = compare_checkpoints(expected.checkpoints, actual.checkpoints)
    if not diff.ok:
        _render_checkpoint_diff_failure(diff)

    message = f"ok: {len(expected.checkpoints)} checkpoints match"
    if diff.first_rng_only_tick is not None:
        message += f"; rng-only drift starts at tick={diff.first_rng_only_tick}"
    typer.echo(message)


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
    from .original.capture import load_capture, parse_player_int_overrides
    from .original.verify import (
        CaptureVerifyError,
        verify_capture,
    )
    from .sim.driver.setup import ReplayRunnerError

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
    from .original.capture import load_capture, summarize_capture_health

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

    from .original.capture import (
        convert_capture_to_checkpoints,
        convert_capture_to_replay,
        default_capture_replay_path,
        load_capture,
        parse_player_int_overrides,
    )
    from .replay import dump_replay
    from .replay.checkpoints import dump_checkpoints_file

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
    from .original import diagnostics_cache, diagnostics_daemon

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
    from .original import divergence_report

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
    from .original import divergence_bisect

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
    from .original import focus_trace

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
    from .original import creature_trajectory

    raise typer.Exit(code=creature_trajectory.main(list(ctx.args)))


@original_app.command(
    "visualize-capture",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_visualize_capture(ctx: typer.Context) -> None:
    """Visualize capture-vs-rewrite drift with hitbox overlays + movement traces."""
    from .original import capture_visualizer

    raise typer.Exit(code=capture_visualizer.main(list(ctx.args)))


@app.callback(invoke_without_command=True)
def cmd_game(
    ctx: typer.Context,
    width: int | None = typer.Option(None, help="window width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="window height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, help="target fps"),
    seed: int | None = typer.Option(None, help="rng seed"),
    demo: bool = typer.Option(False, "--demo", help="enable shareware demo mode"),
    no_intro: bool = typer.Option(False, "--no-intro", help="skip company splashes and intro music"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
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
    """Run the reimplementation game flow (default command)."""
    if ctx.invoked_subcommand:
        return
    from .game import GameConfig, run_game

    config = GameConfig(
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        seed=seed,
        demo_enabled=demo,
        no_intro=no_intro,
        debug=debug,
        preserve_bugs=bool(preserve_bugs),
    )
    run_game(config)


@app.command("config")
def cmd_config(
    path: Path | None = typer.Option(None, help="path to crimson.cfg (default: base-dir/crimson.cfg)"),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Inspect crimson.cfg configuration values."""
    from grim.config import CRIMSON_CFG_NAME, CRIMSON_CFG_STRUCT, load_crimson_cfg

    cfg_path = path if path is not None else base_dir / CRIMSON_CFG_NAME
    config = load_crimson_cfg(cfg_path)
    typer.echo(f"path: {config.path}")
    typer.echo(f"screen: {config.screen_width}x{config.screen_height}")
    typer.echo(f"windowed: {config.windowed_flag}")
    typer.echo(f"bpp: {config.screen_bpp}")
    typer.echo(f"texture_scale: {config.texture_scale}")
    typer.echo("fields:")
    for sub in CRIMSON_CFG_STRUCT.subcons:
        name = sub.name
        if not name:
            continue
        value = config.data[name]
        typer.echo(f"{name}: {_format_cfg_value(value)}")


def _format_cfg_value(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        length = len(value)
        prefix = value.split(b"\x00", 1)[0]
        if prefix and all(32 <= b < 127 for b in prefix):
            text = prefix.decode("ascii", errors="replace")
            return f"{text!r} (len={length})"
        return f"0x{bytes(value).hex()} (len={length})"
    return str(value)


def _parse_int_auto(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"invalid integer: {text!r}") from exc


def _parse_vec2(text: str) -> Vec2:
    raw = text.strip()
    if "," in raw:
        left, right = raw.split(",", 1)
    else:
        parts = raw.split()
        if len(parts) != 2:
            raise typer.BadParameter(f"invalid vec2: {text!r} (expected 'x,y' or 'x y')")
        left, right = parts
    try:
        return Vec2(float(left.strip()), float(right.strip()))
    except ValueError as exc:
        raise typer.BadParameter(f"invalid vec2: {text!r}") from exc


@app.command("spawn-plan")
def cmd_spawn_plan(
    template: str = typer.Argument(..., help="spawn id (e.g. 0x12)"),
    seed: str = typer.Option("0xBEEF", help="MSVCRT rand() seed (e.g. 0xBEEF)"),
    pos: str = typer.Option("512,512", help="spawn position as 'x,y'"),
    heading: float = typer.Option(0.0, help="heading (radians)"),
    terrain_w: float = typer.Option(1024.0, help="terrain width"),
    terrain_h: float = typer.Option(1024.0, help="terrain height"),
    demo_mode_active: bool = typer.Option(True, help="when true, burst effect is skipped"),
    hardcore: bool = typer.Option(False, help="hardcore mode"),
    difficulty: int = typer.Option(0, help="difficulty level"),
    as_json: bool = typer.Option(False, "--json", help="print JSON"),
) -> None:
    """Build and print a spawn plan for a single template id."""
    template_id = _parse_int_auto(template)
    rng = Crand(_parse_int_auto(seed))
    spawn_pos = _parse_vec2(pos)
    env = SpawnEnv(
        terrain_width=terrain_w,
        terrain_height=terrain_h,
        demo_mode_active=demo_mode_active,
        hardcore=hardcore,
        difficulty_level=difficulty,
    )
    plan = build_spawn_plan(template_id, spawn_pos, heading, rng, env)
    if as_json:
        creatures = msgspec.to_builtins(plan.creatures)
        spawn_slots = msgspec.to_builtins(plan.spawn_slots)
        effects = msgspec.to_builtins(plan.effects)
        payload: dict[str, object] = {
            "template_id": template_id,
            "pos": [spawn_pos.x, spawn_pos.y],
            "heading": heading,
            "seed": _parse_int_auto(seed),
            "env": {
                "terrain_width": terrain_w,
                "terrain_height": terrain_h,
                "demo_mode_active": demo_mode_active,
                "hardcore": hardcore,
                "difficulty_level": difficulty,
            },
            "primary": plan.primary,
            "creatures": creatures,
            "spawn_slots": spawn_slots,
            "effects": effects,
            "rng_state": rng.state,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    typer.echo(f"template_id=0x{template_id:02x} ({template_id}) creature={spawn_id_label(template_id)}")
    typer.echo(
        f"pos=({spawn_pos.x:.1f},{spawn_pos.y:.1f}) "
        f"heading={heading:.6f} seed=0x{_parse_int_auto(seed):08x} rng_state=0x{rng.state:08x}",
    )
    typer.echo(
        "env="
        f"demo_mode_active={demo_mode_active} "
        f"hardcore={hardcore} "
        f"difficulty={difficulty} "
        f"terrain={terrain_w:.0f}x{terrain_h:.0f}",
    )
    typer.echo(f"primary={plan.primary} creatures={len(plan.creatures)} slots={len(plan.spawn_slots)} effects={len(plan.effects)}")
    typer.echo("")
    typer.echo("creatures:")
    for idx, c in enumerate(plan.creatures):
        primary = "*" if idx == plan.primary else " "
        typer.echo(
            f"{primary}{idx:02d} type={c.type_id!s:14s} ai={c.ai_mode:2d} flags=0x{int(c.flags):03x} "
            f"pos=({c.pos.x:7.1f},{c.pos.y:7.1f}) health={c.health!s:>6s} size={c.size!s:>6s} link={c.ai_link_parent!s:>3s} "
            f"slot={c.spawn_slot!s:>3s}",
        )
    if plan.spawn_slots:
        typer.echo("")
        typer.echo("spawn_slots:")
        for idx, slot in enumerate(plan.spawn_slots):
            typer.echo(
                f"{idx:02d} owner={slot.owner_creature:02d} timer={slot.timer:.2f} count={slot.count:3d} "
                f"limit={slot.limit:3d} interval={slot.interval:.3f} child=0x{slot.child_template_id:02x}",
            )
    if plan.effects:
        typer.echo("")
        typer.echo("effects:")
        for fx in plan.effects:
            typer.echo(f"burst x={fx.pos.x:.1f} y={fx.pos.y:.1f} count={fx.count}")


@app.command("oracle")
def cmd_oracle(
    seed: int = typer.Option(0xBEEF, help="RNG seed for deterministic runs"),
    input_file: Path | None = typer.Option(None, "--input-file", "-i", help="JSON file with input sequence"),
    max_frames: int = typer.Option(36000, help="Maximum frames to run (default: 10 min at 60fps)"),
    frame_rate: int = typer.Option(60, help="Frame rate for simulation"),
    sample_rate: int = typer.Option(60, "--sample-rate", "-s", help="Emit state every N frames (1=every frame, 60=1/sec)"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    output_mode: str = typer.Option(
        "summary",
        "--output", "-o",
        help="Output mode: full (all entities), summary (fast), hash (ultra-fast), checkpoints (on events only)",
    ),
) -> None:
    """Run headless oracle mode for differential testing.

    Emits JSON game state to stdout. Use with --seed for deterministic runs
    and --input-file for replaying specific input sequences.

    Output modes:
      - summary: Score, kills, player pos/health (default, fast)
      - full: All entities including creatures, projectiles, bonuses
      - hash: SHA256 hash of full state (ultra-fast comparison)
      - checkpoints: Emit only when score/kills/level/weapon changes

    Examples:
        # Fast validation at 1 Hz sampling
        crimson oracle --seed 12345 -i replay.json -s 60 -o summary

        # Full frame-by-frame for debugging divergence
        crimson oracle --seed 12345 -i replay.json -s 1 -o full

        # Ultra-fast hash comparison
        crimson oracle --seed 12345 -i replay.json -o hash

        # Event-driven checkpoints only
        crimson oracle --seed 12345 -i replay.json -o checkpoints
    """
    from .oracle import OracleConfig, OutputMode, run_headless

    # Validate output mode
    mode_map = {
        "full": OutputMode.FULL,
        "summary": OutputMode.SUMMARY,
        "hash": OutputMode.HASH,
        "checkpoints": OutputMode.CHECKPOINTS,
    }
    if output_mode not in mode_map:
        typer.echo(f"Invalid output mode: {output_mode!r}. Choose from: {', '.join(mode_map)}", err=True)
        raise typer.Exit(code=1)

    config = OracleConfig(
        seed=seed,
        input_file=input_file,
        max_frames=max_frames,
        frame_rate=frame_rate,
        sample_rate=sample_rate,
        output_mode=mode_map[output_mode],
        preserve_bugs=bool(preserve_bugs),
    )
    run_headless(config)


def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)


if __name__ == "__main__":
    main()
