"""Pixel-diff two capture directories; write a highlighted diff image per differing shot.

usage: uv run --with pillow --with numpy python scripts/ui_capture/diff.py <before_dir> <after_dir> <diff_dir>
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image


def main() -> int:
    before, after, out = (Path(arg) for arg in sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=True)
    names = sorted({p.name for p in before.glob("*.png")} | {p.name for p in after.glob("*.png")})
    differing = 0
    for name in names:
        a_path, b_path = before / name, after / name
        if not a_path.exists() or not b_path.exists():
            print(f"{name}: missing in {'before' if not a_path.exists() else 'after'}")
            differing += 1
            continue
        a = np.asarray(Image.open(a_path).convert("RGB"), dtype=np.int16)
        b = np.asarray(Image.open(b_path).convert("RGB"), dtype=np.int16)
        if a.shape != b.shape:
            print(f"{name}: size {a.shape} vs {b.shape}")
            differing += 1
            continue
        delta = np.abs(a - b).max(axis=2)
        changed = delta > 0
        count = int(changed.sum())
        if count == 0:
            print(f"{name}: identical")
            continue
        differing += 1
        ys, xs = np.nonzero(changed)
        print(
            f"{name}: {count} px differ (max delta {int(delta.max())}), "
            f"bbox x={xs.min()}..{xs.max()} y={ys.min()}..{ys.max()}",
        )
        overlay = (b * 0.35).astype(np.uint8)
        overlay[changed] = (255, 0, 255)
        Image.fromarray(np.concatenate([a.astype(np.uint8), b.astype(np.uint8), overlay], axis=1)).save(out / name)
    print(f"{differing}/{len(names)} differ")
    return 1 if differing else 0


if __name__ == "__main__":
    sys.exit(main())
