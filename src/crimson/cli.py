from __future__ import annotations

import argparse
import io
import re
import sys
from pathlib import Path

from PIL import Image

from . import jaz, paq


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


def cmd_extract(game_dir: Path, assets_dir: Path) -> int:
    if not game_dir.is_dir():
        raise SystemExit(f"game dir not found: {game_dir}")
    assets_dir.mkdir(parents=True, exist_ok=True)
    paqs = sorted(game_dir.rglob("*.paq"))
    if not paqs:
        raise SystemExit(f"no .paq files under {game_dir}")
    total = 0
    for paq_path in paqs:
        total += _extract_one(paq_path, assets_dir)
    return total


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="paq")
    sub = parser.add_subparsers(dest="cmd", required=True)

    extract_p = sub.add_parser("extract", help="extract all .paq files")
    extract_p.add_argument("game_dir", type=Path)
    extract_p.add_argument("assets_dir", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "extract":
        total = cmd_extract(args.game_dir, args.assets_dir)
        print(f"extracted {total} files")
        return

    raise SystemExit(f"unknown command: {args.cmd}")


if __name__ == "__main__":
    main()
