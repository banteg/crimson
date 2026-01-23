from __future__ import annotations

import io
import inspect
import random
import re
from pathlib import Path

import typer
from PIL import Image

from grim import jaz, paq
from .quests import all_quests
from .quests.types import QuestContext, QuestDefinition, SpawnEntry
from .spawn_templates import spawn_id_label


app = typer.Typer(add_completion=False)

_QUEST_DEFS: dict[str, QuestDefinition] = {quest.level: quest for quest in all_quests()}
_QUEST_BUILDERS = {level: quest.builder for level, quest in _QUEST_DEFS.items()}
_QUEST_TITLES = {level: quest.title for level, quest in _QUEST_DEFS.items()}

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


@app.command("entrypoint")
def cmd_entrypoint(
    base_dir: Path | None = typer.Option(None, help="base path for runtime files (default: artifacts/runtime)"),
    assets_dir: Path | None = typer.Option(None, help="assets root (default: artifacts/assets)"),
) -> None:
    """Print the planned entrypoint boot sequence."""
    from .entrypoint import (
        DEFAULT_ASSETS_DIR,
        DEFAULT_BASE_DIR,
        EntrypointConfig,
        format_entrypoint_plan,
        run_entrypoint,
    )

    config = EntrypointConfig(
        base_dir=DEFAULT_BASE_DIR if base_dir is None else base_dir,
        assets_dir=DEFAULT_ASSETS_DIR if assets_dir is None else assets_dir,
    )
    plan = run_entrypoint(config)
    typer.echo(format_entrypoint_plan(plan))


def _call_builder(builder, ctx: QuestContext, rng: random.Random | None) -> list[SpawnEntry]:
    params = inspect.signature(builder).parameters
    if "rng" in params:
        return builder(ctx, rng=rng)
    return builder(ctx)


def _format_entry(idx: int, entry: SpawnEntry) -> str:
    creature = spawn_id_label(entry.spawn_id)
    return (
        f"{idx:02d}  t={entry.trigger_ms:5d}  "
        f"id=0x{entry.spawn_id:02x} ({entry.spawn_id:2d})  "
        f"creature={creature:10s}  "
        f"count={entry.count:2d}  "
        f"x={entry.x:7.1f}  y={entry.y:7.1f}  heading={entry.heading:7.3f}"
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
    for idx, entry in enumerate(entries, start=1):
        typer.echo(_format_entry(idx, entry))


@app.command("view")
def cmd_view(
    name: str = typer.Argument(..., help="view name (e.g. empty)"),
    width: int = typer.Option(1024, help="window width"),
    height: int = typer.Option(768, help="window height"),
    fps: int = typer.Option(60, help="target fps"),
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
    ctx = ViewContext(assets_dir=assets_dir)
    params = inspect.signature(view_def.factory).parameters
    if "ctx" in params:
        view = view_def.factory(ctx=ctx)
    else:
        view = view_def.factory()
    title = f"{view_def.title} — Crimsonland"
    run_view(view, width=width, height=height, title=title, fps=fps)


@app.command("game")
def cmd_game(
    width: int | None = typer.Option(None, help="window width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="window height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, help="target fps"),
    seed: int | None = typer.Option(None, help="rng seed"),
    base_dir: Path = typer.Option(
        Path("artifacts") / "runtime",
        help="base path for runtime files (default: artifacts/runtime)",
    ),
    assets_dir: Path | None = typer.Option(
        None,
        help="assets root (default: base-dir; missing .paq copied from game_bins/)",
    ),
) -> None:
    """Run the reimplementation entrypoint."""
    from .game import GameConfig, run_game

    config = GameConfig(
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        seed=seed,
    )
    run_game(config)


@app.command("config")
def cmd_config(
    path: Path | None = typer.Option(None, help="path to crimson.cfg (default: base-dir/crimson.cfg)"),
    base_dir: Path = typer.Option(
        Path("artifacts") / "runtime",
        help="base path for runtime files (default: artifacts/runtime)",
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


def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)


if __name__ == "__main__":
    main()
