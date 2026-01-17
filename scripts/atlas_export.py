from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image

from crimson.atlas import GRID_SIZE_BY_CODE, grid_size_for_index, rect_for_index, uv_for_index

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Slice a Crimsonland sprite sheet into frames.")
    parser.add_argument("--image", type=Path, required=True, help="source image path")
    group = parser.add_mutually_exclusive_group(required=True)
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
        help="output directory (default: output/atlas/<name>/grid<grid>/)",
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
    args = parser.parse_args()

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
    out_dir = args.out_dir or Path("output") / "atlas" / base_name / f"grid{grid}"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.manifest or (out_dir / "manifest.json")

    pad = max(3, len(str(max(indices))))
    frames: list[dict[str, object]] = []
    for idx in indices:
        rect = rect_for_index(image.width, image.height, grid, idx)
        uv = uv_for_index(grid, idx)
        frame = image.crop(rect)
        filename = f"{args.frame_prefix}{idx:0{pad}d}.png"
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
        "image": args.image.as_posix(),
        "grid": grid,
        "source_size": [image.width, image.height],
        "cell_size": [image.width // grid, image.height // grid],
        "frame_count": len(frames),
        "indices": indices,
        "frames": frames,
    }
    manifest.update(meta)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {len(frames)} frames to {out_dir}")
    print(f"wrote manifest to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
