from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image

from crimson.atlas import GRID_SIZE_BY_CODE, SPRITE_TABLE, grid_size_for_index, rect_for_index, uv_for_index

DEFAULT_GRIDS = {2, 4, 8, 16}


def parse_indices(raw: str, max_index: int) -> list[int]:
    indices: list[int] = []
    for chunk in raw.split(","):
        token = chunk.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = int(start_s.strip(), 0)
            end = int(end_s.strip(), 0)
            if end < start:
                start, end = end, start
            for idx in range(start, end + 1):
                if 0 <= idx <= max_index:
                    indices.append(idx)
            continue
        idx = int(token, 0)
        if 0 <= idx <= max_index:
            indices.append(idx)
    seen = set()
    ordered = []
    for idx in indices:
        if idx in seen:
            continue
        seen.add(idx)
        ordered.append(idx)
    return ordered


def resolve_grid(args: argparse.Namespace) -> tuple[int, dict[str, int]]:
    meta: dict[str, int] = {}
    if args.grid is not None:
        grid = args.grid
    elif args.table_index is not None:
        try:
            grid = grid_size_for_index(args.table_index)
        except IndexError as exc:
            raise SystemExit(f"invalid table index: {args.table_index}") from exc
        meta["table_index"] = args.table_index
    else:
        try:
            grid = GRID_SIZE_BY_CODE[args.grid_code]
        except KeyError as exc:
            raise SystemExit(f"invalid grid code: {args.grid_code}") from exc
        meta["grid_code"] = args.grid_code
    if grid not in DEFAULT_GRIDS:
        raise SystemExit(f"unsupported grid size: {grid}")
    return grid, meta


def export_frames(
    image_path: Path,
    grid: int,
    indices: list[int] | None,
    out_dir: Path,
    manifest_path: Path,
    frame_prefix: str,
    meta: dict[str, object],
) -> None:
    image = Image.open(image_path)
    max_index = grid * grid - 1
    if indices is None:
        indices = list(range(grid * grid))
    else:
        indices = parse_indices(",".join(str(i) for i in indices), max_index)
    if not indices:
        raise SystemExit("no valid indices to export")

    out_dir.mkdir(parents=True, exist_ok=True)
    pad = max(3, len(str(max(indices))))
    frames: list[dict[str, object]] = []
    for idx in indices:
        rect = rect_for_index(image.width, image.height, grid, idx)
        uv = uv_for_index(grid, idx)
        frame = image.crop(rect)
        filename = f"{frame_prefix}{idx:0{pad}d}.png"
        frame.save(out_dir / filename)
        x0, y0, x1, y1 = rect
        frames.append(
            {
                "index": idx,
                "path": filename,
                "rect": [x0, y0, x1 - x0, y1 - y0],
                "uv": [round(uv[0], 6), round(uv[1], 6), round(uv[2], 6), round(uv[3], 6)],
            }
        )

    manifest = {
        "image": image_path.as_posix(),
        "grid": grid,
        "source_size": [image.width, image.height],
        "cell_size": [image.width // grid, image.height // grid],
        "frame_count": len(frames),
        "indices": indices,
        "frames": frames,
    }
    manifest.update(meta)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def resolve_texture_path(texture: str, assets_root: Path) -> Path | None:
    candidate = Path(texture)
    if candidate.exists():
        return candidate
    if not candidate.is_absolute():
        alt = assets_root / candidate
        if alt.exists():
            return alt
    if candidate.suffix.lower() == ".jaz":
        png = candidate.with_suffix(".png")
        if png.exists():
            return png
        if not candidate.is_absolute():
            alt = (assets_root / candidate).with_suffix(".png")
            if alt.exists():
                return alt
    if not candidate.suffix:
        for ext in (".png", ".jaz"):
            alt = candidate.with_suffix(ext)
            if alt.exists():
                return alt
            if not candidate.is_absolute():
                alt_root = assets_root / alt
                if alt_root.exists():
                    return alt_root
    return None


def export_all(args: argparse.Namespace) -> int:
    usage_path = args.usage_json or Path("output") / "atlas" / "atlas_usage.json"
    if not usage_path.exists():
        raise SystemExit(f"usage json not found: {usage_path}")

    payload = json.loads(usage_path.read_text(encoding="utf-8"))
    textures = payload.get("textures", [])
    if not textures:
        raise SystemExit("usage json has no textures")

    output_root = args.out_root or Path("artifacts") / "atlas" / "frames"
    assets_root = args.assets_root
    exported = 0

    for entry in textures:
        texture = str(entry.get("texture", ""))
        image_path = resolve_texture_path(texture, assets_root)
        if image_path is None or not image_path.exists():
            print(f"skip: missing texture {texture}")
            continue

        grids: set[int] = set()
        for direct in entry.get("direct", []):
            grid = direct.get("grid")
            if isinstance(grid, int):
                grids.add(grid)
        for idx in entry.get("table_indices", []):
            if isinstance(idx, int) and 0 <= idx < len(SPRITE_TABLE):
                code = SPRITE_TABLE[idx][0]
                grid = GRID_SIZE_BY_CODE.get(code)
                if grid:
                    grids.add(grid)
        grids = {g for g in grids if g in DEFAULT_GRIDS}
        if not grids:
            continue

        try:
            rel = image_path.relative_to(assets_root)
        except ValueError:
            rel = image_path.name
        if isinstance(rel, Path):
            rel_dir = rel.parent
            rel_stem = rel.stem
        else:
            rel_dir = Path()
            rel_stem = Path(str(rel)).stem

        used_indices: dict[int, list[int]] = {g: [] for g in grids}
        for direct in entry.get("direct", []):
            grid = direct.get("grid")
            idx = direct.get("index")
            if isinstance(grid, int) and isinstance(idx, int) and grid in used_indices:
                if idx not in used_indices[grid]:
                    used_indices[grid].append(idx)

        for grid in sorted(grids):
            out_dir = output_root / rel_dir / rel_stem / f"grid{grid}"
            manifest_path = out_dir / "manifest.json"
            meta = {
                "source_texture": texture,
                "used_indices": used_indices[grid],
            }
            export_frames(
                image_path=image_path,
                grid=grid,
                indices=None,
                out_dir=out_dir,
                manifest_path=manifest_path,
                frame_prefix=args.frame_prefix,
                meta=meta,
            )
            exported += 1
            print(f"exported {image_path} grid {grid} -> {out_dir}")

    print(f"exported {exported} atlas variants")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Slice a Crimsonland sprite sheet into frames.")
    parser.add_argument("--image", type=Path, help="source image path")
    parser.add_argument("--all", action="store_true", help="export all textures from usage json")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--grid", type=int, help="grid size (2, 4, 8, 16)")
    group.add_argument("--table-index", type=int, help="sprite table index (0-16)")
    group.add_argument(
        "--grid-code",
        type=lambda v: int(v, 0),
        help="grid code (0x80, 0x40, 0x20, 0x10)",
    )
    parser.add_argument(
        "--indices",
        type=str,
        help="frame indices (e.g. 0-3,8,10-12). Defaults to full grid.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="output directory (default: artifacts/atlas/<name>/grid<grid>/)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="manifest path (default: <out-dir>/manifest.json)",
    )
    parser.add_argument(
        "--frame-prefix",
        type=str,
        default="frame_",
        help="filename prefix for frames (default: frame_)",
    )
    parser.add_argument(
        "--usage-json",
        type=Path,
        help="atlas usage json (default: artifacts/atlas/atlas_usage.json)",
    )
    parser.add_argument(
        "--out-root",
        type=Path,
        help="root output directory for --all (default: artifacts/atlas/frames/)",
    )
    parser.add_argument(
        "--assets-root",
        type=Path,
        default=Path("artifacts") / "assets" / "crimson",
        help="assets root for resolving textures (default: artifacts/assets/crimson)",
    )
    args = parser.parse_args()

    if args.all:
        return export_all(args)

    if args.image is None:
        raise SystemExit("missing --image (or use --all)")
    if args.grid is None and args.table_index is None and args.grid_code is None:
        raise SystemExit("missing grid selection (use --grid/--table-index/--grid-code)")

    grid, meta = resolve_grid(args)
    image = Image.open(args.image)
    max_index = grid * grid - 1
    if args.indices:
        indices = parse_indices(args.indices, max_index)
    else:
        indices = list(range(grid * grid))
    if not indices:
        raise SystemExit("no valid indices to export")

    base_name = args.image.stem
    out_dir = args.out_dir or Path("artifacts") / "atlas" / base_name / f"grid{grid}"
    manifest_path = args.manifest or (out_dir / "manifest.json")

    export_frames(
        image_path=args.image,
        grid=grid,
        indices=indices,
        out_dir=out_dir,
        manifest_path=manifest_path,
        frame_prefix=args.frame_prefix,
        meta=meta,
    )

    print(f"wrote {len(indices)} frames to {out_dir}")
    print(f"wrote manifest to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
