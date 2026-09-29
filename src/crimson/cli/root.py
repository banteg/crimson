from __future__ import annotations

import io
import json
import os
import re
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

import msgspec
import typer
from PIL import Image

from grim import jaz, paq
from grim.geom import Vec2
from grim.rand import Crand

from ..creatures.spawn import SpawnId, spawn_id_label
from ..paths import default_runtime_dir

app = typer.Typer(add_completion=False)

if TYPE_CHECKING:
    from ..creatures.runtime import CreaturePool
    from ..quests.types import QuestDefinition, SpawnEntry
    from ..sim.gameplay_state import GameplayState


@cache
def _quest_defs() -> dict[str, QuestDefinition]:
    from ..quests import QUESTS

    return {quest.level.text: quest for quest in QUESTS}


_SEP_RE = re.compile(r"[\\/]+")


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
    terrain_slots = _format_id_list(quest.terrain_slots)
    return [
        f"time_limit_ms={quest.time_limit_ms}",
        f"start_weapon_id={quest.start_weapon_id}",
        f"unlock_perk_id={_format_id(quest.unlock_perk_id)}",
        f"unlock_weapon_id={_format_id(quest.unlock_weapon_id)}",
        f"terrain_slots={terrain_slots}",
    ]


@app.command("quests")
def cmd_quests(
    level: str = typer.Argument(..., help="quest level, e.g. 1.1"),
    player_count: int = typer.Option(1, help="player count"),
    seed: int | None = typer.Option(None, help="seed for randomized quests"),
    sort: bool = typer.Option(False, help="sort output by trigger time"),
    show_plan: bool = typer.Option(False, help="include each template's pool allocations (creatures, spawn slots)"),
) -> None:
    """Print quest spawn scripts for a given level."""
    from ..quests.types import QuestContext

    quest_defs = _quest_defs()
    quest = quest_defs.get(level)
    if quest is None:
        available = ", ".join(sorted(quest_defs))
        typer.echo(f"unknown level {level!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    builder = quest.builder
    title = quest.title
    entries = builder(QuestContext(player_count=player_count, rng=Crand(seed) if seed is not None else Crand()))
    if sort:
        entries = sorted(entries, key=lambda e: (e.trigger_ms, e.spawn_id, e.pos.x, e.pos.y))
    typer.echo(f"Quest {level} {title} ({len(entries)} entries)")
    typer.echo("Meta: " + "; ".join(_format_meta(quest)))

    plan_cache: dict[SpawnId, tuple[int, int]] = {}
    if show_plan:
        for entry in entries:
            if entry.spawn_id in plan_cache:
                continue
            pool, _state, _returned = spawn_template_into_fresh_pool(entry.spawn_id, Vec2(512.0, 512.0), 0.0, seed=0)
            plan_cache[entry.spawn_id] = (
                sum(creature.active for creature in pool.entries),
                sum(slot.owner_creature >= 0 for slot in pool.spawn_slots),
            )
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

    from ..debug_views import all_views, view_by_name
    from ..runtime_resources_view import RuntimeResourcesView

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
    instance = view_def.factory(ctx)
    title = f"{view_def.title} — Crimsonland"
    run_view(
        RuntimeResourcesView(instance.view, assets_dir=assets_dir),
        width=width,
        height=height,
        title=title,
        fps=fps,
        hooks=instance.hooks,
    )


@app.callback(invoke_without_command=True)
def cmd_game(
    ctx: typer.Context,
    width: int | None = typer.Option(None, help="game resolution width, saved to crimson.cfg"),
    height: int | None = typer.Option(None, help="game resolution height, saved to crimson.cfg"),
    windowed: bool | None = typer.Option(
        None,
        "--windowed/--fullscreen",
        help="window mode, saved to crimson.cfg; toggle in game with alt+enter",
    ),
    fps: int = typer.Option(60, help="target fps"),
    seed: int | None = typer.Option(None, help="rng seed"),
    no_intro: bool = typer.Option(False, "--no-intro", help="skip company splashes and intro music"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
    rtx: bool = typer.Option(False, "--rtx", help="enable non-canonical RTX render mode"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    replay_checkpoints: bool = typer.Option(
        False,
        "--replay-checkpoints",
        help="write per-tick checkpoint sidecars next to saved replays (parity debugging)",
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
    """Run the reimplementation game flow (default command)."""
    if ctx.invoked_subcommand:
        return
    from ..game import GameConfig, run_game

    config = GameConfig(
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        windowed=windowed,
        fps=fps,
        seed=seed,
        no_intro=no_intro,
        debug=debug,
        rtx=bool(rtx),
        preserve_bugs=bool(preserve_bugs),
        replay_checkpoints=bool(replay_checkpoints),
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
    raw_fields = CRIMSON_CFG_STRUCT.parse(cfg_path.read_bytes())
    typer.echo(f"path: {config.path}")
    typer.echo(f"screen: {config.display.width}x{config.display.height}")
    typer.echo(f"windowed: {config.display.windowed}")
    typer.echo(f"bpp: {config.display.bpp}")
    typer.echo(f"texture_scale: {config.display.texture_scale}")
    typer.echo("fields:")
    for sub in CRIMSON_CFG_STRUCT.subcons:
        name = sub.name
        if not name:
            continue
        value = raw_fields[name]
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


def spawn_template_into_fresh_pool(
    template_id: SpawnId,
    pos: Vec2,
    heading: float,
    *,
    seed: int,
    hardcore: bool = False,
    quest_fail_retry_count: int = 0,
) -> tuple[CreaturePool, GameplayState, int]:
    """Run `creature_spawn_template` once into an empty pool; returns the pool, state and returned index."""

    from ..creatures.runtime import CreaturePool
    from ..sim.gameplay_state import GameplayState

    pool = CreaturePool()
    state = GameplayState(rng=Crand(seed), hardcore=hardcore, quest_fail_retry_count=quest_fail_retry_count)
    returned = pool.spawn_template(template_id, pos, heading, state=state, detail_preset=5)
    return pool, state, returned


@app.command("spawn-plan")
def cmd_spawn_plan(
    template: str = typer.Argument(..., help="spawn id (e.g. 0x12)"),
    seed: str = typer.Option("0xBEEF", help="MSVCRT rand() seed (e.g. 0xBEEF)"),
    pos: str = typer.Option("512,512", help="spawn position as 'x,y'"),
    heading: float = typer.Option(0.0, help="heading (radians)"),
    hardcore: bool = typer.Option(False, help="hardcore mode"),
    quest_fail_retry_count: int = typer.Option(0, help="quest fail retry count"),
    as_json: bool = typer.Option(False, "--json", help="print JSON"),
) -> None:
    """Spawn one template into an empty creature pool and print the resulting pool state."""
    template_id_raw = _parse_int_auto(template)
    try:
        template_id = SpawnId(template_id_raw)
    except ValueError as exc:
        raise typer.BadParameter(f"invalid spawn template id: {template!r}") from exc
    seed_value = _parse_int_auto(seed)
    spawn_pos = _parse_vec2(pos)
    pool, state, returned = spawn_template_into_fresh_pool(
        template_id,
        spawn_pos,
        heading,
        seed=seed_value,
        hardcore=hardcore,
        quest_fail_retry_count=quest_fail_retry_count,
    )
    creatures = [(index, creature) for index, creature in enumerate(pool.entries) if creature.active]
    spawn_slots = [(index, slot) for index, slot in enumerate(pool.spawn_slots) if slot.owner_creature >= 0]
    effect_count = len(state.effects.iter_active())
    if as_json:
        payload: dict[str, object] = {
            "template_id": int(template_id),
            "pos": [spawn_pos.x, spawn_pos.y],
            "heading": heading,
            "seed": seed_value,
            "env": {
                "hardcore": hardcore,
                "quest_fail_retry_count": quest_fail_retry_count,
            },
            "returned": returned,
            "creatures": [
                {
                    "index": index,
                    "type_id": int(creature.type_id),
                    "ai_mode": int(creature.ai_mode),
                    "flags": int(creature.flags),
                    "pos": [creature.pos.x, creature.pos.y],
                    "target_offset": None
                    if creature.target_offset is None
                    else [creature.target_offset.x, creature.target_offset.y],
                    "heading": creature.heading,
                    "phase_seed": creature.phase_seed,
                    "link_index": creature.link_index,
                    "orbit_angle": creature.orbit_angle,
                    "orbit_radius": creature.orbit_radius,
                    "health": creature.hp,
                    "max_health": creature.max_hp,
                    "move_speed": creature.move_speed,
                    "reward_value": creature.reward_value,
                    "size": creature.size,
                    "contact_damage": creature.contact_damage,
                    "tint": [creature.tint.r, creature.tint.g, creature.tint.b, creature.tint.a],
                }
                for index, creature in creatures
            ],
            "spawn_slots": [{"index": index, **msgspec.to_builtins(slot)} for index, slot in spawn_slots],
            "effect_count": effect_count,
            "rng_state": state.rng.state,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    typer.echo(f"template_id=0x{int(template_id):02x} ({int(template_id)}) creature={spawn_id_label(template_id)}")
    typer.echo(
        f"pos=({spawn_pos.x:.1f},{spawn_pos.y:.1f}) "
        f"heading={heading:.6f} seed=0x{seed_value:08x} rng_state=0x{state.rng.state:08x}",
    )
    typer.echo(f"env=hardcore={hardcore} quest_fail_retry_count={quest_fail_retry_count}")
    typer.echo(f"returned={returned} active={len(creatures)} slots={len(spawn_slots)} effects={effect_count}")
    typer.echo("")
    typer.echo("creatures:")
    for index, c in creatures:
        returned_mark = "*" if index == returned else " "
        typer.echo(
            f"{returned_mark}{index:03d} type={c.type_id.name:10s} ai={int(c.ai_mode):2d} flags=0x{int(c.flags):03x} "
            f"pos=({c.pos.x:7.1f},{c.pos.y:7.1f}) health={c.hp:7.1f} size={c.size:5.1f} link={c.link_index}",
        )
    if spawn_slots:
        typer.echo("")
        typer.echo("spawn_slots:")
        for index, slot in spawn_slots:
            typer.echo(
                f"{index:02d} owner={slot.owner_creature:03d} timer={slot.timer:.2f} count={slot.count:3d} "
                f"limit={slot.limit:3d} interval={slot.interval:.3f} child=0x{slot.child_template_id:02x}",
            )
