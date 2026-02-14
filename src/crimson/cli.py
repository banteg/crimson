from __future__ import annotations

import io
import inspect
import ipaddress
import json
import random
import re
import sys
from pathlib import Path
from dataclasses import fields, is_dataclass
from typing import Any, cast

import typer
from PIL import Image

from grim import jaz, paq
from grim.geom import Vec2
from grim.rand import Crand
from .paths import default_runtime_dir
from .creatures.spawn import SpawnEnv, build_spawn_plan, spawn_id_label
from .quests import all_quests
from .quests.types import QuestContext, QuestDefinition, SpawnEntry


app = typer.Typer(add_completion=False)
replay_app = typer.Typer(add_completion=False)
original_app = typer.Typer(add_completion=False)
lan_app = typer.Typer(add_completion=False)
app.add_typer(replay_app, name="replay")
app.add_typer(original_app, name="original")
app.add_typer(lan_app, name="lan")

_QUEST_DEFS: dict[str, QuestDefinition] = {quest.level: quest for quest in all_quests()}
_QUEST_BUILDERS = {level: quest.builder for level, quest in _QUEST_DEFS.items()}
_QUEST_TITLES = {level: quest.title for level, quest in _QUEST_DEFS.items()}

_SEP_RE = re.compile(r"[\\/]+")


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


def _safe_relpath(name: str) -> Path:
    parts = [p for p in _SEP_RE.split(name) if p]
    if not parts:
        raise ValueError("empty entry name")
    for part in parts:
        if part in (".", ".."):
            raise ValueError(f"unsafe path part: {part!r}")
    return Path(*parts)


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
    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=bool(preserve_bugs))
    params = inspect.signature(view_def.factory).parameters
    if "ctx" in params:
        view = view_def.factory(ctx=ctx)
    else:
        view = view_def.factory()
    title = f"{view_def.title} — Crimsonland"
    run_view(view, width=width, height=height, title=title, fps=fps)


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
    """Host a LAN lockstep session from CLI."""
    from .game import GameConfig, run_game
    from .game.types import LanSessionConfig, LanSessionMode, PendingLanSession
    from .quests.types import parse_level

    mode_name = str(mode).strip().lower()
    resolved_mode: LanSessionMode
    if mode_name == "survival":
        resolved_mode = "survival"
    elif mode_name == "rush":
        resolved_mode = "rush"
    elif mode_name == "quests":
        resolved_mode = "quests"
    else:
        raise typer.BadParameter(
            f"unsupported mode {mode!r}; expected one of: survival, rush, quests",
            param_hint="--mode",
        )
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
            host_ip="",
            port=int(port),
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    run_game(
        GameConfig(
            base_dir=base_dir,
            assets_dir=assets_dir,
            width=width,
            height=height,
            fps=fps,
            debug=bool(debug),
            preserve_bugs=False,
            pending_lan_session=pending,
        )
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
    """Join a LAN lockstep session from CLI."""
    from .game import GameConfig, run_game
    from .game.types import LanSessionConfig, PendingLanSession

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
            host_ip=host_ip,
            port=int(port),
            preserve_bugs=False,
        ),
        auto_start=True,
    )
    run_game(
        GameConfig(
            base_dir=base_dir,
            assets_dir=assets_dir,
            width=width,
            height=height,
            fps=fps,
            debug=bool(debug),
            pending_lan_session=pending,
        )
    )


@replay_app.command("play")
def cmd_replay_play(
    replay_file: Path = typer.Argument(..., help="replay file path (.crdemo.gz)"),
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
    from grim.app import run_view
    from grim.console import create_console
    from grim.config import ensure_crimson_cfg
    from grim.view import ViewContext

    from .assets_fetch import download_missing_paqs
    from .modes.replay_playback_mode import ReplayPlaybackMode

    if assets_dir is None:
        assets_dir = base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(base_dir)
    if width is None:
        width = cfg.screen_width
    if height is None:
        height = cfg.screen_height
    console = create_console(base_dir, assets_dir=assets_dir)
    download_missing_paqs(assets_dir, console)

    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=False)
    view = ReplayPlaybackMode(ctx, replay_path=replay_file)
    title = f"Replay — {replay_file.name}"
    run_view(view, width=width, height=height, title=title, fps=fps)


@replay_app.command("verify")
def cmd_replay_verify(
    replay_file: Path = typer.Argument(..., help="replay file path (.crdemo.gz)"),
    checkpoints_file: Path | None = typer.Option(
        None,
        "--checkpoints",
        help="checkpoint sidecar path (default: <replay>.checkpoints.json.gz)",
    ),
    max_ticks: int | None = typer.Option(None, help="stop after N ticks (default: full replay)"),
    strict_events: bool = typer.Option(
        False,
        "--strict-events/--lenient-events",
        help="fail on unsupported replay events/perk picks (default: lenient)",
    ),
    trace_rng: bool = typer.Option(
        False,
        "--trace-rng",
        help="include presentation RNG draw marks in verification checkpoints",
    ),
) -> None:
    """Verify a replay by comparing headless checkpoints with a sidecar file."""
    import hashlib

    from .game_modes import GameMode
    from .original.diff import compare_checkpoints
    from .replay import load_replay
    from .replay.checkpoints import default_checkpoints_path, load_checkpoints_file
    from .sim.runners import ReplayRunnerError, run_rush_replay, run_survival_replay

    replay_bytes = Path(replay_file).read_bytes()
    replay_sha256 = hashlib.sha256(replay_bytes).hexdigest()
    replay = load_replay(replay_bytes)

    if checkpoints_file is None:
        checkpoints_file = default_checkpoints_path(replay_file)
    checkpoints_path = Path(checkpoints_file)
    if not checkpoints_path.is_file():
        typer.echo(f"checkpoints file not found: {checkpoints_path}", err=True)
        raise typer.Exit(code=1)

    expected = load_checkpoints_file(checkpoints_path)
    if expected.replay_sha256 and str(expected.replay_sha256) != str(replay_sha256):
        typer.echo(
            f"warning: checkpoints replay_sha256 mismatch (checkpoints={expected.replay_sha256!r}, replay={replay_sha256!r})",
            err=True,
        )

    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected.checkpoints}
    actual = []

    mode = int(replay.header.game_mode_id)
    try:
        if mode == int(GameMode.SURVIVAL):
            result = run_survival_replay(
                replay,
                max_ticks=max_ticks,
                strict_events=bool(strict_events),
                trace_rng=bool(trace_rng),
                checkpoints_out=actual,
                checkpoint_ticks=checkpoint_ticks,
            )
        elif mode == int(GameMode.RUSH):
            result = run_rush_replay(
                replay,
                max_ticks=max_ticks,
                trace_rng=bool(trace_rng),
                checkpoints_out=actual,
                checkpoint_ticks=checkpoint_ticks,
            )
        else:
            typer.echo(f"unsupported replay game_mode_id={mode}", err=True)
            raise typer.Exit(code=1)
    except ReplayRunnerError as exc:
        typer.echo(f"replay verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    diff = compare_checkpoints(expected.checkpoints, actual)
    if not diff.ok:
        failure = diff.failure
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

    message = (
        f"ok: {len(expected.checkpoints)} checkpoints match; ticks={result.ticks} "
        f"score_xp={result.score_xp} kills={result.creature_kill_count}"
    )
    if diff.first_rng_only_tick is not None:
        message += f"; rng-only drift starts at tick={diff.first_rng_only_tick}"
    typer.echo(message)


@replay_app.command("diff-checkpoints")
def cmd_replay_diff_checkpoints(
    expected_file: Path = typer.Argument(..., help="expected checkpoints sidecar (.json.gz)"),
    actual_file: Path = typer.Argument(..., help="actual checkpoints sidecar (.json.gz)"),
) -> None:
    """Compare two checkpoint sidecars and report the first divergence."""
    from .replay.checkpoints import load_checkpoints_file
    from .original.diff import compare_checkpoints

    expected = load_checkpoints_file(Path(expected_file))
    actual = load_checkpoints_file(Path(actual_file))
    diff = compare_checkpoints(expected.checkpoints, actual.checkpoints)
    if not diff.ok:
        failure = diff.failure
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
) -> None:
    """Verify capture ticks directly against rewrite simulation state."""
    from .original.capture import load_capture, parse_player_int_overrides
    from .original.verify import (
        CaptureVerifyError,
        verify_capture,
    )
    from .sim.runners import ReplayRunnerError

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

    if not result.ok:
        failure = result.failure
        assert failure is not None
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
    typer.echo(message)


@original_app.command("convert-capture")
def cmd_replay_convert_capture(
    capture_file: Path = typer.Argument(
        ...,
        help="capture file (.json/.json.gz)",
    ),
    output_file: Path = typer.Argument(..., help="output checkpoints sidecar (.json.gz)"),
    replay_file: Path | None = typer.Option(
        None,
        "--replay",
        help="output replay path (.crdemo.gz); default: derive from checkpoints path",
    ),
    replay_sha256: str = typer.Option(
        "",
        help="optional replay sha256 to store in the converted sidecar",
    ),
    seed: int | None = typer.Option(
        None,
        help="seed override for replay reconstruction (default: infer from capture rng telemetry)",
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

    from .replay import dump_replay
    from .replay.checkpoints import dump_checkpoints_file
    from .original.capture import (
        convert_capture_to_checkpoints,
        convert_capture_to_replay,
        default_capture_replay_path,
        load_capture,
        parse_player_int_overrides,
    )

    capture = load_capture(Path(capture_file))
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    replay = convert_capture_to_replay(
        capture,
        seed=seed,
        aim_scheme_overrides_by_player=aim_scheme_overrides,
    )
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
    except Exception as exc:
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
        )
    )


@original_app.command(
    "bisect-divergence",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "help_option_names": []},
)
def cmd_replay_bisect_divergence(ctx: typer.Context) -> None:
    """Binary-search the first divergent tick and emit a compact repro bundle."""
    from .original import divergence_bisect

    raise typer.Exit(code=divergence_bisect.main(list(ctx.args)))


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
        )
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


def _dc_to_dict(obj: object) -> dict[str, object]:
    if not is_dataclass(obj):
        raise TypeError(f"expected dataclass instance, got {type(obj).__name__}")
    dc_obj = cast(Any, obj)
    return {f.name: getattr(dc_obj, f.name) for f in fields(dc_obj)}


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
            "creatures": [_dc_to_dict(c) for c in plan.creatures],
            "spawn_slots": [_dc_to_dict(s) for s in plan.spawn_slots],
            "effects": [_dc_to_dict(e) for e in plan.effects],
            "rng_state": rng.state,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    typer.echo(f"template_id=0x{template_id:02x} ({template_id}) creature={spawn_id_label(template_id)}")
    typer.echo(
        f"pos=({spawn_pos.x:.1f},{spawn_pos.y:.1f}) "
        f"heading={heading:.6f} seed=0x{_parse_int_auto(seed):08x} rng_state=0x{rng.state:08x}"
    )
    typer.echo(
        "env="
        f"demo_mode_active={demo_mode_active} "
        f"hardcore={hardcore} "
        f"difficulty={difficulty} "
        f"terrain={terrain_w:.0f}x{terrain_h:.0f}"
    )
    typer.echo(f"primary={plan.primary} creatures={len(plan.creatures)} slots={len(plan.spawn_slots)} effects={len(plan.effects)}")
    typer.echo("")
    typer.echo("creatures:")
    for idx, c in enumerate(plan.creatures):
        primary = "*" if idx == plan.primary else " "
        typer.echo(
            f"{primary}{idx:02d} type={c.type_id!s:14s} ai={c.ai_mode:2d} flags=0x{int(c.flags):03x} "
            f"pos=({c.pos.x:7.1f},{c.pos.y:7.1f}) health={c.health!s:>6s} size={c.size!s:>6s} link={c.ai_link_parent!s:>3s} "
            f"slot={c.spawn_slot!s:>3s}"
        )
    if plan.spawn_slots:
        typer.echo("")
        typer.echo("spawn_slots:")
        for idx, slot in enumerate(plan.spawn_slots):
            typer.echo(
                f"{idx:02d} owner={slot.owner_creature:02d} timer={slot.timer:.2f} count={slot.count:3d} "
                f"limit={slot.limit:3d} interval={slot.interval:.3f} child=0x{slot.child_template_id:02x}"
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
