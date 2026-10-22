"""Complete RTX world-frame timings and optional HDR/SDR captures.

Run from the checkout being measured with its uv environment and an absolute
path to this script. Compare two checkouts in alternating runs. Capture in a
separate run: readback/encoding is outside timing but perturbs subsequent work.
Requires game assets in the runtime directory. replay19 uses the installed
replays/19-survival.crd; other scenes use deterministic scripted native inputs.
Includes smoke, terrain bakes, sprites and tone mapping; excludes HUD and swap.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import time
from pathlib import Path

import numpy as np

ROOT = Path.cwd()
OUT = Path(__file__).resolve().parent
import scene as fx
from crimson.render.rtx.material_lights import collect_material_lights
from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.paths import default_runtime_dir
from crimson.replay import load_replay_file
from crimson.runtime_boot import boot_runtime
from grim import canvas
from grim.assets import load_runtime_resources, unload_runtime_resources
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode
from grim.view import ViewContext
from tests.support.factories import make_creature_state

# The only GPU synchronization is at complete frame boundaries.
import ctypes.util

library = ctypes.util.find_library("OpenGL") or ctypes.util.find_library("GL")
if library is None:
    raise RuntimeError("OpenGL library needed for synchronized timings")
GL = ctypes.CDLL(library)
GL.glFinish.restype = None
GL.glGetString.argtypes = [ctypes.c_uint]
GL.glGetString.restype = ctypes.c_char_p


def finish():
    rl.rl_draw_render_batch_active()
    GL.glFinish()


def stats(v):
    return {
        "samples": len(v),
        "median_ms": float(np.median(v)),
        "p95_ms": float(np.percentile(v, 95)),
        "p99_ms": float(np.percentile(v, 99)),
        "max_ms": float(max(v)),
    }


def pixel(target, w, h):
    image = rl.load_image_from_texture(target.texture)
    try:
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        return np.frombuffer(rl.ffi.buffer(image.data, w * h * 4), np.uint8).reshape(h, w, 4)[::-1, :, :3].copy()
    finally:
        rl.unload_image(image)


class ReplayScene:
    def __init__(self, mode, path):
        self.mode, self.path, self.rows = mode, path, []

    def advance(self, t, *, present):
        target = round((182 + t) * 60)
        while self.mode.tick_index < target:
            self.mode.run(min(2, target - self.mode.tick_index), quiet=True)
        self.mode.set_frame_dt(1 / 60)
        row = {
            "time": 182 + t,
            "tick": self.mode.tick_index,
            "creatures": sum(c.active for c in self.mode.runtime.world.creatures.entries),
        }
        self.rows.append(row)
        return row

    def proof(self):
        import hashlib

        return {
            "replay_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
            "start": 182,
            "smoke_warmup_start": 167,
            "frames": self.rows,
        }


def timed_draw(runtime, target):
    finish()
    start = time.perf_counter()
    with texture_mode(target):
        runtime.draw()
    submitted = time.perf_counter()
    finish()
    return {"completed_ms": (time.perf_counter() - start) * 1000, "submission_ms": (submitted - start) * 1000}


def summary(rows):
    return {key: stats([row[key] for row in rows]) for key in rows[0] if key.endswith("_ms")}


def counts(runtime):
    frame = runtime.build_render_frame()
    lights = collect_material_lights(frame, view_center=Vec2(512, 512))
    grid = runtime.render_resources.ground.reflection_occlusion.grid
    return dict(
        creatures=sum(c.active for c in frame.creatures.entries),
        lights=len(lights),
        bodies=grid.body_count if grid else 0,
        grid_references=grid.references if grid else 0,
        grid_floats=len(grid.values) if grid else 0,
        smoke_steps=frame.smoke.simulation.executed_steps if frame.smoke else None,
    )


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--scene", choices=["dense", "minigun", "swarmers", "nuke", "replay19"], default="dense")
    ap.add_argument("--width", type=int, default=1024)
    ap.add_argument("--frames", type=int, default=240)
    args = ap.parse_args()
    OUT = args.output
    OUT.mkdir(parents=True, exist_ok=True)
    if args.frames <= 90:
        ap.error("--frames must exceed the 90-frame warmup")
    w, h = args.width, args.width * 3 // 4
    base = default_runtime_dir()
    boot = boot_runtime(base, base, width=w, height=h)
    cfg = boot.config
    cfg.audio.sound_disabled = cfg.audio.music_disabled = True
    cfg.display.width, cfg.display.height, cfg.display.detail_preset = w, h, 5
    cfg.display.smoke_enabled = True
    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.set_config_flags(int(rl.ConfigFlags.FLAG_WINDOW_HIDDEN))
    rl.init_window(64, 64, "RTX pipeline profiling")
    canvas.width = lambda: w
    canvas.height = lambda: h
    resources = load_runtime_resources(base)
    replay = (
        base / "replays/19-survival.crd"
        if args.scene == "replay19"
        else ROOT / "tests/fixtures/replays/survival-238852.crd"
    )
    mode = ReplayPlaybackMode(
        ViewContext(assets_dir=base, preserve_bugs=False),
        replay=load_replay_file(replay),
        config=cfg,
        console=boot.console,
        max_ticks=12000 if args.scene == "replay19" else 1,
        rtx=True,
        plays_music=False,
    )
    mode.open()
    mode.run(1, quiet=True)
    runtime = mode.runtime
    runtime.render_resources.process_ground_pending()
    terrain = runtime.terrain_setup
    if terrain is not None:
        runtime.apply_terrain_setup(terrain)
        runtime.render_resources.process_ground_pending()
    scene = (
        ReplayScene(mode, replay)
        if args.scene == "replay19"
        else fx.Scene(runtime, args.scene, perks=args.scene == "dense")
    )
    runtime.view_cap = Vec2(1024, 768)
    if args.scene == "dense":
        for i in range(3, 99):
            angle = i * 2.399963
            radius = 90 + (i % 12) * 23
            c = make_creature_state(
                pos=Vec2(512 + math.cos(angle) * radius, 450 + math.sin(angle) * radius), hp=50000, size=36,
            )
            c.move_speed = c.contact_damage = 0
            runtime.world.creatures.entries[i] = c
    target = rl.load_render_texture(w, h)
    if args.scene == "replay19":
        runtime.render_resources.set_simulated_smoke(False)
        while mode.tick_index < 167 * 60:
            mode.run(min(240, 167 * 60 - mode.tick_index), quiet=True)
            runtime.render_resources.process_ground_pending()
        runtime.render_resources.set_simulated_smoke(True)
        while mode.tick_index < 182 * 60:
            mode.run(min(2, 182 * 60 - mode.tick_index), quiet=True)
            mode.set_frame_dt(1 / 30)
            with texture_mode(target):
                runtime.draw()
        finish()
    rows = []
    try:
        for n in range(args.frames):
            start = time.perf_counter()
            scene.advance((n + 1) / 60, present=True)
            update = (time.perf_counter() - start) * 1000
            if args.scene != "replay19":
                runtime.camera = Vec2(0, -128)
            row = timed_draw(runtime, target)
            row["update_ms"] = update
            row["update_plus_completed_ms"] = update + row["completed_ms"]
            row.update(counts(runtime))
            rows.append(row)
            if args.capture and n in (0, 30, 90, 120, args.frames - 1):
                from PIL import Image

                hdr = runtime.render_resources.hdr.target
                image = rl.load_image_from_texture(hdr.texture)
                try:
                    rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
                    pixels = np.frombuffer(rl.ffi.buffer(image.data, w * h * 16), np.float32).reshape(h, w, 4).copy()
                    np.savez_compressed(OUT / f"{args.scene}-{w}-{n}-hdr.npz", pixels=pixels)
                finally:
                    rl.unload_image(image)
                Image.fromarray(pixel(target, w, h)).save(OUT / f"{args.scene}-{w}-{n}.png")
            if n % 60 == 0:
                print(args.scene, w, n, round(row["completed_ms"], 2), flush=True)
        data = {
            "commit": fx.SOURCE_COMMIT,
            "scene": args.scene,
            "resolution": [w, h],
            "gpu": GL.glGetString(0x1F01).decode(),
            "warmup_frames": 90,
            "timings": summary(rows[90:]),
            "frames": rows,
            "method": __doc__,
            "fixture_proof": scene.proof(),
        }
        tag = f"{args.scene}-{w}"
        (OUT / f"{tag}.json").write_text(json.dumps(data, indent=2))
        print(json.dumps(data["timings"], indent=2), flush=True)
    finally:
        rl.unload_render_texture(target)
        mode.close()
        unload_runtime_resources(resources)
        rl.close_window()


if __name__ == "__main__":
    main()
