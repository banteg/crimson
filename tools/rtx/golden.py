"""RTX golden scenes: the same replay moments captured classic and RTX by the native client, for art reviews.

    uv run python tools/rtx/golden.py capture --game <game folder> --out <dir>
    uv run python tools/rtx/golden.py compare <before dir> <after dir> --out <dir>

The game folder holds crimson.paq, sfx.paq and music.paq (a client's runtime folder works). Each scene in
scenes.toml is a replay and a tick; the client seeks a little before it (smoke and wet blood need history), pauses on
the tick and saves its frame (CRIMSON_CAPTURE_TICK), with GPU time per pass (CRIMSON_GPU_TIMERS) over the frames
leading to it. Captures tonemap for SDR, so they read the same on any display.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tomllib
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / "crimson-core/build/app/crimson"
MODES = ("classic", "rtx")


def scenes() -> list[dict]:
    return tomllib.loads((HERE / "scenes.toml").read_text())["scene"]


def capture_scene(scene: dict, mode: str, game: Path, out: Path, client: Path) -> dict:
    """One scene in one mode: its frame as <scene>-<mode>.png and the median GPU ms per pass before it."""
    replay = game / "replays" / "golden" / Path(scene["replay"]).name
    replay.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / scene["replay"], replay)
    tick = int(scene["tick"])
    work = out / f".{scene['name']}-{mode}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    env = {
        **os.environ,
        "CRIMSON_CAPTURE": str(work),
        "CRIMSON_CAPTURE_TICK": str(tick),
        "CRIMSON_WATCH": str(replay.relative_to(game)),
        "CRIMSON_WATCH_SEEK": str(max(1, tick - int(scene.get("history", 300)))),
        "CRIMSON_GPU_TIMERS": "1",
        "CRIMSON_MUTE": "1",
        "CRIMSON_RTX": "1" if mode == "rtx" else "0",
    }
    result = subprocess.run([str(client), str(game)], env=env, capture_output=True, text=True, timeout=600, check=False)
    frame = work / f"tick_{tick}.ppm"
    if not frame.exists():
        sys.exit(f"{scene['name']} ({mode}): no frame at tick {tick}\n{result.stderr[-2000:]}")
    Image.open(frame).save(out / f"{scene['name']}-{mode}.png")
    # The frames drawn while playback approached the tick, not the held frames after it.
    passes: dict[str, list[float]] = {}
    for line in result.stderr.splitlines():
        if not line.startswith("gpu tick="):
            continue
        fields = line.split()
        drawn = int(fields[1].removeprefix("tick="))
        if tick - 60 <= drawn < tick:
            for field in fields[2:]:
                name, ms = field.split("=")
                passes.setdefault(name, []).append(float(ms))
    shutil.rmtree(work)
    return {name: statistics.median(values) for name, values in passes.items()}


def capture(args: argparse.Namespace) -> None:
    args.out.mkdir(parents=True, exist_ok=True)
    chosen = [s for s in scenes() if not args.scene or s["name"] in args.scene]
    timings = {}
    for scene in chosen:
        for mode in args.modes.split(","):
            gpu = capture_scene(scene, mode, args.game, args.out, args.client)
            timings[f"{scene['name']}-{mode}"] = gpu
            print(f"{scene['name']:<16} {mode:<8} gpu {sum(gpu.values()):6.2f} ms  ground {gpu.get('ground', 0):6.2f} ms")
    (args.out / "timings.json").write_text(json.dumps(timings, indent=1, sort_keys=True) + "\n")


def compare(args: argparse.Namespace) -> None:
    """Each frame of `before` beside `after` (and their difference), with the mean change per scene."""
    args.out.mkdir(parents=True, exist_ok=True)
    before_gpu = json.loads((args.before / "timings.json").read_text())
    after_gpu = json.loads((args.after / "timings.json").read_text())
    for path in sorted(args.before.glob("*.png")):
        other = args.after / path.name
        if not other.exists():
            continue
        a, b = Image.open(path).convert("RGB"), Image.open(other).convert("RGB")
        delta = np.abs(np.asarray(a, np.int16) - np.asarray(b, np.int16))
        heat = Image.fromarray(np.clip(delta.max(axis=2) * 4, 0, 255).astype(np.uint8)).convert("RGB")
        sheet = Image.new("RGB", (a.width * 3, a.height))
        for i, image in enumerate((a, b, heat)):
            sheet.paste(image, (i * a.width, 0))
        sheet.save(args.out / path.name)
        key = path.stem
        ms_before = sum(before_gpu.get(key, {}).values())
        ms_after = sum(after_gpu.get(key, {}).values())
        print(f"{key:<26} mean change {delta.mean():6.2f}  gpu {ms_before:6.2f} -> {ms_after:6.2f} ms")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    grab = commands.add_parser("capture", help="capture the scenes classic and RTX")
    grab.add_argument("--game", type=Path, required=True, help="a game folder with the paq files")
    grab.add_argument("--out", type=Path, required=True)
    grab.add_argument("--client", type=Path, default=CLIENT)
    grab.add_argument("--modes", default=",".join(MODES))
    grab.add_argument("--scene", action="append", help="only these scenes (repeatable)")
    grab.set_defaults(run=capture)
    diff = commands.add_parser("compare", help="sheets of two captures side by side")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--out", type=Path, required=True)
    diff.set_defaults(run=compare)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
