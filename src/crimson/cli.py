from __future__ import annotations

import io
import inspect
import random
import re
from pathlib import Path

import typer
from PIL import Image

from . import jaz, paq
from .quests import tier1, tier2
from .quests.types import QuestContext, SpawnEntry


app = typer.Typer(add_completion=False)

_QUEST_BUILDERS = {**tier1.TIER1_BUILDERS, **tier2.TIER2_BUILDERS}
_QUEST_TITLES = {**tier1.TIER1_TITLES, **tier2.TIER2_TITLES}

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


@app.command("font")
def cmd_font(
    assets_dir: Path = typer.Option(
        Path("artifacts") / "assets",
        help="assets root (default: ./artifacts/assets)",
    ),
    out_path: Path = typer.Option(
        Path("artifacts") / "fonts" / "small_font_sample.png",
        help="output image path",
    ),
    text: str | None = typer.Option(None, help="text to render"),
    text_file: Path | None = typer.Option(None, help="path to a text file"),
    scale: float = typer.Option(2.0, help="scale factor"),
) -> None:
    """Render a sample image with the small font."""
    if text and text_file:
        typer.echo("use either --text or --text-file, not both", err=True)
        raise typer.Exit(code=1)
    if text_file is not None:
        text = text_file.read_text(encoding="utf-8", errors="replace")
    from . import font

    if text is None:
        text = font.DEFAULT_SAMPLE
    font_data = font.load_small_font_from_assets(assets_dir)
    font.render_sample(font_data, out_path, text=text, scale=scale)
    typer.echo(f"wrote {out_path}")


def _call_builder(builder, ctx: QuestContext, rng: random.Random | None) -> list[SpawnEntry]:
    params = inspect.signature(builder).parameters
    if "rng" in params:
        return builder(ctx, rng=rng)
    return builder(ctx)


def _format_entry(idx: int, entry: SpawnEntry) -> str:
    return (
        f"{idx:02d}  t={entry.trigger_ms:5d}  "
        f"id=0x{entry.spawn_id:02x} ({entry.spawn_id:2d})  "
        f"count={entry.count:2d}  "
        f"x={entry.x:7.1f}  y={entry.y:7.1f}  heading={entry.heading:7.3f}"
    )


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
    builder = _QUEST_BUILDERS.get(level)
    title = _QUEST_TITLES.get(level, "unknown")
    if builder is None:
        available = ", ".join(sorted(_QUEST_BUILDERS))
        typer.echo(f"unknown level {level!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    ctx = QuestContext(width=width, height=height, player_count=player_count)
    rng = random.Random(seed) if seed is not None else random.Random()
    entries = _call_builder(builder, ctx, rng)
    if sort:
        entries = sorted(entries, key=lambda e: (e.trigger_ms, e.spawn_id, e.x, e.y))
    typer.echo(f"Quest {level} {title} ({len(entries)} entries)")
    for idx, entry in enumerate(entries, start=1):
        typer.echo(_format_entry(idx, entry))


def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)


if __name__ == "__main__":
    main()
