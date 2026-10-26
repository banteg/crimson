"""RTX golden scenes: the same replay moments captured classic and RTX by the native client, for art reviews.

    uv run python tools/rtx/golden.py capture --game <game folder> --out <dir>
    uv run python tools/rtx/golden.py compare <before dir> <after dir> --out <dir>
    uv run python tools/rtx/golden.py python --game <game folder> --out <dir>
    uv run python tools/rtx/golden.py parity --game <game folder> --out <dir>

The game folder holds crimson.paq, sfx.paq and music.paq (a client's runtime folder works). Each scene in
scenes.toml is a replay and a tick; the client seeks a little before it (smoke and wet blood need history), pauses on
the tick and saves its frame (CRIMSON_CAPTURE_TICK), with GPU time per pass from a profile of the frames leading to
it (CRIMSON_PROFILE, tools/profile.py), the simulation's share left out. Captures tonemap for SDR, so they read the same on any display.

`python` draws the same moments with the Python port, as the client does; `parity` captures them with both and
compares the two, so the client's port of the RTX passes and the Python one show where they part.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / "crimson-core/build/app/crimson"
MODES = ("classic", "rtx")
# The replay bar's band along the bottom of a paused client capture (VIEWER_BAR_H, host/viewer.inc), logical pixels.
VIEWER_BAR_H = 48
# A pixel differs when its worst channel is more than this many levels apart.
THRESHOLD = 16
# The farthest whole-pixel shift `compare` aligns by.
SHIFT = 4
# The client's window in logical pixels; both sides draw it at the display's density (2048x1536 on a Retina Mac).
LOGICAL = (1024, 768)


def scenes() -> list[dict]:
    return tomllib.loads((HERE / "scenes.toml").read_text())["scene"]


def chosen_scenes(args: argparse.Namespace) -> list[dict]:
    return [s for s in scenes() if not args.scene or s["name"] in args.scene]


def seek_tick(scene: dict) -> int:
    """Where playback starts: `history` ticks before the scene's, which the fluid smoke and wet blood build up over."""
    return max(1, int(scene["tick"]) - int(scene.get("history", 300)))


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
        "CRIMSON_WATCH_SEEK": str(seek_tick(scene)),
        # Scenes share replays, and runs repeat: each replay prepares once per client build and mode.
        "CRIMSON_WATCH_CACHE": "1",
        "CRIMSON_PROFILE": str(work / "profile.jsonl"),
        # Every frame's GPU passes: a capture's own frame times do not count.
        "CRIMSON_PROFILE_GPU": "1",
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
    for line in (work / "profile.jsonl").read_text().splitlines()[1:]:
        drawn = json.loads(line)
        if tick - 60 <= drawn["tick"] < tick:
            for name, ms in drawn.get("gpu", {}).items():
                # The frame timer spans the simulation's ticks before anything draws: a GPU timer counts that CPU
                # time as idle GPU time, so it is no measure of drawing. Drawing before the world (decal bakes,
                # heat stamps) has timers of its own.
                if name != "frame":
                    passes.setdefault(name, []).append(ms)
    shutil.rmtree(work)
    return {name: statistics.median(values) for name, values in passes.items()}


def render_python(args: argparse.Namespace) -> None:
    """The scenes drawn by the Python port as the client captures them (`<scene>-<mode>.png`): undrawn to the
    client's seek, then a frame per tick up to the scene's tick, the HUD over it, SDR. `--window n` also saves the
    frames n ticks either side (`<scene>-<mode>@<offset>.png`), and `--views` the scene's tick in `rtxdebug` views
    (`<scene>-rtx-<view>.png`)."""
    from crimson.modes.replay_playback_mode import ReplayPlaybackMode
    from crimson.render.rtx.debug import RtxDebugView
    from crimson.replay import load_replay
    from crimson.runtime_boot import boot_runtime
    from grim.assets import load_runtime_resources, unload_runtime_resources
    from grim.raylib_api import rl
    from grim.view import ViewContext

    def draw(paint: Callable[[], None], keep: bool) -> Image.Image | None:
        rl.begin_drawing()
        rl.clear_background(rl.BLACK)
        paint()
        rl.rl_draw_render_batch_active()
        frame = None
        if keep:
            image = rl.load_image_from_screen()
            colors = rl.load_image_colors(image)
            size = (image.width, image.height)
            frame = Image.frombuffer("RGBA", size, rl.ffi.buffer(colors, size[0] * size[1] * 4)).convert("RGB")
            rl.unload_image_colors(colors)
            rl.unload_image(image)
        rl.end_drawing()
        return frame

    args.out.mkdir(parents=True, exist_ok=True)
    # The game folder's crimson.cfg and paq files, as the client reads them, in the client's window.
    boot = boot_runtime(args.game, args.game, width=LOGICAL[0], height=LOGICAL[1])
    boot.config.audio.sound_disabled = boot.config.audio.music_disabled = True
    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_HIDDEN | rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)
    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.init_window(*LOGICAL, "golden")
    resources = load_runtime_resources(args.game)
    ctx = ViewContext(assets_dir=args.game, preserve_bugs=False)
    for scene in chosen_scenes(args):
        replay = load_replay((ROOT / scene["replay"]).read_bytes())
        tick = int(scene["tick"])
        for mode in args.modes.split(","):
            playback = ReplayPlaybackMode(ctx, replay=replay, config=boot.config, console=boot.console,
                                          rtx=mode == "rtx")
            playback.open()
            # The client's unattended clock moves 16 ms a frame, which the HUD's animations take.
            playback.set_frame_dt(0.016)
            # The client's seek runs undrawn to its tick and draws it; playback then draws every tick (a frame that
            # banks no tick holds the last one), so the stateful passes (smoke, wet blood) see the same frames.
            playback.run(seek_tick(scene) - 1, quiet=True)
            # A seek settles the HUD's counters too: the XP count does not count up to the run's.
            playback.settle_hud()
            while playback.tick_index < tick + args.window:
                playback.run(1, quiet=True)
                offset = playback.tick_index - tick
                frame = draw(playback.draw, abs(offset) <= args.window)
                if frame is None:
                    continue
                frame.save(args.out / f"{scene['name']}-{mode}{f'@{offset:+d}' if offset else ''}.png")
                if offset:
                    continue
                # Drawing again without a tick changes nothing the later ticks draw from (bar a level here and
                # there). The HUD and aim overlays are where the world alone draws differently, a little widened.
                world = draw(playback.runtime.draw, True)
                worst = np.abs(np.asarray(frame, np.int16) - np.asarray(world, np.int16)).max(axis=2)
                hud = Image.fromarray(((worst > 2) * 255).astype(np.uint8)).filter(ImageFilter.MaxFilter(7))
                hud.save(args.out / f"{scene['name']}-{mode}-hud.png")
                for view in args.views.split(",") if mode == "rtx" and args.views else ():
                    playback.runtime.rtx_debug = RtxDebugView.parse(view)
                    draw(playback.draw, False)
                    draw(playback.draw, True).save(args.out / f"{scene['name']}-rtx-{view}.png")
                playback.runtime.rtx_debug = RtxDebugView.SHADED
            playback.close()
            print(f"{scene['name']:<16} {mode:<8} python", flush=True)
    unload_runtime_resources(resources)
    rl.close_window()


def capture(args: argparse.Namespace) -> None:
    args.out.mkdir(parents=True, exist_ok=True)
    timings = {}
    for scene in chosen_scenes(args):
        for mode in args.modes.split(","):
            gpu = capture_scene(scene, mode, args.game, args.out, args.client)
            timings[f"{scene['name']}-{mode}"] = gpu
            print(f"{scene['name']:<16} {mode:<8} gpu {sum(gpu.values()):6.2f} ms  ground {gpu.get('ground', 0):6.2f} ms")
    (args.out / "timings.json").write_text(json.dumps(timings, indent=1, sort_keys=True) + "\n")


def difference(a: np.ndarray, b: np.ndarray, region: np.ndarray) -> dict:
    """How far apart two frames are over a region, in levels out of 255: the mean over channels, the 99th
    percentile of the worst channel and the share of pixels whose worst channel is over THRESHOLD."""
    delta = np.abs(a[region] - b[region])
    worst = delta.max(axis=1)
    return {"mean": round(float(delta.mean()), 2), "p99": int(np.percentile(worst, 99)),
            "over": round(float((worst > THRESHOLD).mean()) * 100, 2)}


def aligned(a: np.ndarray, b: np.ndarray, world: np.ndarray) -> tuple[np.ndarray, int, int]:
    """`a` moved by the whole pixels (within SHIFT) that bring it closest to `b` over the world: one renderer placing
    everything a pixel off from the other differs at every edge, which would drown out what else differs."""
    inner = world[SHIFT:-SHIFT, SHIFT:-SHIFT]
    target = b[SHIFT:-SHIFT, SHIFT:-SHIFT][inner]
    height, width = world.shape

    def distance(dx: int, dy: int) -> float:
        moved = a[SHIFT + dy:height - SHIFT + dy, SHIFT + dx:width - SHIFT + dx]
        return float(np.abs(moved[inner] - target).mean())

    dx, dy = min(((dx, dy) for dy in range(-SHIFT, SHIFT + 1) for dx in range(-SHIFT, SHIFT + 1)),
                 key=lambda shift: distance(*shift))
    return np.roll(a, (-dy, -dx), axis=(0, 1)), dx, dy


def compare(args: argparse.Namespace) -> None:
    """Each scene of `before` beside `after` with their difference (`<scene>-<mode>.jpg`, the full-size map as
    `<scene>-<mode>-diff.png`) and how far apart they are (summary.json): the world, and apart from it the HUD
    (where `after` has a `-hud.png` mask, as the Python renders do) and the replay bar's band, which a paused client
    capture shows. `before` is first aligned to `after` to the pixel (the shift is reported, with the world's mean
    difference unaligned); of `after`'s frames near the tick (`@<offset>`) the closest stands in."""
    args.out.mkdir(parents=True, exist_ok=True)
    timings = [json.loads(path.read_text()) if path.exists() else {}
               for path in (args.before / "timings.json", args.after / "timings.json")]
    summary = {}
    for key in [f"{scene['name']}-{mode}" for scene in scenes() for mode in MODES]:
        path = args.before / f"{key}.png"
        frames = {0: args.after / f"{key}.png"} | {
            int(other.stem.rpartition("@")[2]): other for other in args.after.glob(f"{key}@*.png")}
        if not path.exists() or not frames[0].exists():
            continue
        a = np.asarray(Image.open(path).convert("RGB"), np.float32)
        bar = np.zeros(a.shape[:2], bool)
        bar[a.shape[0] - round(VIEWER_BAR_H * a.shape[0] / LOGICAL[1]):] = True
        hud_path = args.after / f"{key}-hud.png"
        hud = (np.asarray(Image.open(hud_path)) > 0) & ~bar if hud_path.exists() else np.zeros_like(bar)
        # The edges the alignment wraps around belong to no region.
        edge = np.ones_like(bar)
        edge[SHIFT:-SHIFT, SHIFT:-SHIFT] = False
        world = ~bar & ~hud & ~edge
        unaligned = {offset: (difference(a, b, world), b) for offset, other in frames.items()
                     for b in [np.asarray(Image.open(other).convert("RGB"), np.float32)]}
        offset = min(unaligned, key=lambda offset: unaligned[offset][0]["mean"])
        raw, b = unaligned[offset]
        a, dx, dy = aligned(a, b, world)
        result = summary[key] = {
            "world": difference(a, b, world), "world_unaligned": raw, "shift": [dx, dy], "tick_offset": offset,
            "hud": difference(a, b, hud) if hud.any() else None, "bar": difference(a, b, bar),
            "gpu_ms": [round(sum(gpu.get(key, {}).values()), 2) for gpu in timings]}
        # The difference map, four times over; the regions outside the world dimmed.
        worst = np.abs(a - b).max(axis=2) * 4
        worst[~world] *= 0.35
        heat = Image.fromarray(np.clip(worst, 0, 255).astype(np.uint8)).convert("RGB")
        heat.save(args.out / f"{key}-diff.png")
        sheet = Image.new("RGB", (a.shape[1] * 3, a.shape[0]))
        for i, image in enumerate((Image.fromarray(a.astype(np.uint8)), Image.fromarray(b.astype(np.uint8)), heat)):
            sheet.paste(image, (i * a.shape[1], 0))
        sheet.resize((LOGICAL[0] * 3, LOGICAL[1]), Image.Resampling.LANCZOS).save(args.out / f"{key}.jpg", quality=90)
        world_stats = result["world"]
        hud_mean = "-" if result["hud"] is None else f"{result['hud']['mean']:5.2f}"
        gpu = "" if not all(result["gpu_ms"]) else "  gpu {:6.2f} -> {:6.2f} ms".format(*result["gpu_ms"])
        print(f"{key:<20} world mean {world_stats['mean']:5.2f} p99 {world_stats['p99']:3d} "
              f"over {world_stats['over']:5.2f}%  unaligned {raw['mean']:5.2f}  shift {dx:+d},{dy:+d}  "
              f"tick {offset:+d}  hud {hud_mean}  bar {result['bar']['mean']:5.2f}{gpu}", flush=True)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")


def parity(args: argparse.Namespace) -> None:
    """The scenes captured by the client and drawn by the Python port, then compared: classic shows how far the
    two draw apart anyway (filtering, placement), so RTX beyond it is the RTX ports diverging."""
    capture(argparse.Namespace(**(vars(args) | {"out": args.out / "client"})))
    render_python(argparse.Namespace(**(vars(args) | {"out": args.out / "python"})))
    compare(argparse.Namespace(before=args.out / "client", after=args.out / "python", out=args.out))


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
    port = commands.add_parser("python", help="draw the scenes' RTX frames with the Python port")
    port.add_argument("--game", type=Path, required=True, help="a game folder with the paq files")
    port.add_argument("--out", type=Path, required=True)
    port.add_argument("--modes", default=",".join(MODES))
    port.add_argument("--scene", action="append", help="only these scenes (repeatable)")
    port.add_argument("--window", type=int, default=0, help="also save the frames this many ticks either side")
    port.add_argument("--views", default="", help="rtxdebug views to save at the scene's tick (comma-separated)")
    port.set_defaults(run=render_python)
    diff = commands.add_parser("compare", help="sheets of two captures side by side")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--out", type=Path, required=True)
    diff.set_defaults(run=compare)
    both = commands.add_parser("parity", help="the client beside the Python port, scene by scene")
    both.add_argument("--game", type=Path, required=True, help="a game folder with the paq files")
    both.add_argument("--out", type=Path, required=True)
    both.add_argument("--client", type=Path, default=CLIENT)
    both.add_argument("--modes", default=",".join(MODES))
    both.add_argument("--scene", action="append", help="only these scenes (repeatable)")
    both.add_argument("--window", type=int, default=0, help="let the Python frame this many ticks either side stand in")
    both.add_argument("--views", default="", help="rtxdebug views the Python port saves too (comma-separated)")
    both.set_defaults(run=parity)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
