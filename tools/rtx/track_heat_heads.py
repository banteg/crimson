"""Bake animation-frame heat centers with OpenCV Lucas–Kanade optical flow.

Run: uv run --with 'opencv-python-headless>=4.13,<4.14' python tools/rtx/track_heat_heads.py --assets artifacts/assets
OpenCV is an authoring dependency only. Runtime code consumes the generated
byte coordinates through the unused green/blue channels of the heat tint.
"""

import argparse
import io
import json
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw

from grim.assets import _select_texture_asset, load_paq_entries
from grim.jaz import decode_jaz_bytes

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "src/crimson/render/rtx/heat_heads.json"
# One head seed in the original 64px cell; the library tracks every subsequent
# pose. The lizard keeps more of the approved torso placement than the zombie.
PROFILES = (("zombie", 32, (30.5, 28.5), 1.0), ("lizard", 16, (43.0, 31.0), .35))


def track(atlas: Image.Image, count: int, seed: tuple[float, float]) -> tuple[np.ndarray, float]:
    w, h = atlas.width // 8, atlas.height // 8
    # A mirrored strip plays forwards then backwards; 15 -> 0 is not its loop seam.
    order = list(range(count)) if count == 32 else [*range(count), *reversed(range(count))]
    frames = []
    for index in order:
        x, y = index % 8 * w, index // 8 * h
        rgba = np.asarray(atlas.crop((x, y, x + w, y + h))).astype(np.float32) / 255
        rgb = np.rint(rgba[:, :, :3] * rgba[:, :, 3, None] * 255).astype(np.uint8)
        frames.append(cv2.resize(cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY), (w * 4, h * 4),
                                 interpolation=cv2.INTER_CUBIC))
    offsets = np.array([(x, y) for y in (-1., 0., 1.) for x in (-1., 0., 1.)], np.float32)
    center = np.array(seed, np.float64) * np.array([w, h]) / 64
    points = ((center.astype(np.float32) + offsets) * 4).reshape(-1, 1, 2)
    centers = [center.copy()]
    parameters = {
        "winSize": (31, 31), "maxLevel": 2,
        "criteria": (cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 50, .001), "minEigThreshold": 1e-5,
    }
    for phase in range(1, len(order) + 1):
        previous, following = frames[(phase - 1) % len(order)], frames[phase % len(order)]
        forward, status, _ = cv2.calcOpticalFlowPyrLK(previous, following, points, None, **parameters)
        backward, back_status, _ = cv2.calcOpticalFlowPyrLK(following, previous, forward, None, **parameters)
        valid = (status.ravel().astype(bool) & back_status.ravel().astype(bool)
                 & (np.linalg.norm((backward - points).reshape(-1, 2), axis=1) < 2.))
        if valid.sum() < 3:
            raise RuntimeError(f"Lost head tracking at phase {phase}; inspect the seed and artwork")
        center = center + np.median((forward - points).reshape(-1, 2)[valid], axis=0) / 4
        centers.append(center.copy())
        points = ((center.astype(np.float32) + offsets) * 4).reshape(-1, 1, 2)
    positions = np.array(centers)
    drift = positions[-1] - positions[0]
    if np.linalg.norm(drift) > 2:
        raise RuntimeError(f"Head tracker failed cycle closure: {drift} pixels")
    # The animation is a closed loop: distribute the small accumulated drift,
    # then average the two observations of each mirrored frame.
    positions = positions[:-1] - np.arange(len(order))[:, None] / len(order) * drift
    result = np.array([positions[np.array(order) == index].mean(axis=0) for index in range(count)])
    return (result + .5) / np.array([w, h]), float(np.linalg.norm(drift))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    parser.add_argument("--preview-dir", type=Path)
    args = parser.parse_args()
    cv2.setNumThreads(1)
    entries = load_paq_entries(args.assets)
    result = {}
    for name, count, seed, blend in PROFILES:
        path, data = _select_texture_asset(entries, f"game/{name}.jaz")
        if data is None:
            raise FileNotFoundError(path)
        atlas = (decode_jaz_bytes(data).composite_image() if path.endswith(".jaz")
                 else Image.open(io.BytesIO(data))).convert("RGBA")
        positions, drift = track(atlas, count, seed)
        centers = np.array([.525, .5]) + blend * (positions - np.array([.525, .5]))
        encoded = np.floor(centers * 255 + .5).astype(int)
        if not ((encoded > 0).all() and (encoded < 255).all()):
            raise ValueError("Heat centers must lie inside their atlas cells")
        result[name] = encoded.tolist()
        print(f"{name}: tracked {count} frames, {drift:.3f}px cycle drift, {blend:.0%} head following")
        if args.preview_dir is not None:
            args.preview_dir.mkdir(parents=True, exist_ok=True)
            sheet = Image.new("RGB", (8 * 128, ((count + 7) // 8) * 148), (25, 28, 35))
            draw = ImageDraw.Draw(sheet)
            w, h = atlas.width // 8, atlas.height // 8
            for index, (head, heat) in enumerate(zip(positions, centers, strict=True)):
                x, y = index % 8 * w, index // 8 * h
                cell = Image.new("RGBA", (w, h), (25, 28, 35, 255))
                cell.alpha_composite(atlas.crop((x, y, x + w, y + h)))
                left, top = index % 8 * 128, index // 8 * 148 + 20
                sheet.paste(cell.resize((128, 128), Image.Resampling.NEAREST).convert("RGB"), (left, top))
                draw.text((left, top - 16), str(index), fill="white")
                for point, color in ((head, "#00ff77"), (heat, "#ffbb33")):
                    px, py = left + point[0] * 128, top + point[1] * 128
                    draw.ellipse((px - 2, py - 2, px + 2, py + 2), fill=color)
            sheet.save(args.preview_dir / f"{name}-tracking.png")
    lines = ["{"]
    for index, (name, frames) in enumerate(result.items()):
        lines.append(f"  {json.dumps(name)}: [")
        lines.extend(f"    {json.dumps(point)}{',' if i < len(frames) - 1 else ''}"
                     for i, point in enumerate(frames))
        lines.append("  ]" + ("," if index < len(result) - 1 else ""))
    args.out.write_text("\n".join([*lines, "}"]) + "\n")


if __name__ == "__main__":
    main()
