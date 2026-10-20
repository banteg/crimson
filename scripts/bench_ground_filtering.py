"""Synchronized production GroundRenderer bake timings; excludes loading and shader compilation."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import statistics
import time
from pathlib import Path

from crimson.sim.terrain_generate import terrain_generate
from crimson.terrain_slots import Q1_TERRAIN_SLOTS
from grim.assets import _load_texture_asset_from_bytes, _select_texture_asset, load_paq_entries_from_path
from grim.rand import Crand
from grim.raylib_api import rl
from grim.shaders import _ALPHA_TEST_FS_330, _ALPHA_TEST_VS_330, AlphaTestShader
from grim.terrain_render import GroundRenderer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paq", type=Path, required=True)
    args = parser.parse_args()
    entries = load_paq_entries_from_path(args.paq)
    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.set_config_flags(int(rl.ConfigFlags.FLAG_WINDOW_HIDDEN))
    rl.init_window(64, 64, "Ground filtering benchmark")
    library = ctypes.util.find_library("OpenGL") or ctypes.util.find_library("GL")
    if library is None:
        raise RuntimeError("OpenGL library needed for synchronized timings")
    finish = ctypes.CDLL(library).glFinish
    finish.restype = None
    textures = []
    for path in ("ter/ter_q1_base.jaz", "ter/ter_q1_tex1.jaz"):
        name, data = _select_texture_asset(entries, path)
        texture = _load_texture_asset_from_bytes(name, data)
        assert texture is not None
        textures.append(texture)
    layers = terrain_generate(Crand(0xC0FFEE), Q1_TERRAIN_SLOTS).layers
    results = {}
    try:
        # Interleave modes to avoid attributing a gradual temperature change to filtering.
        grounds = {}
        for mode in ("baseline", "bilinear", "cubic"):
            fragment = _ALPHA_TEST_FS_330.replace(
                "alphaBilinear(texture0, fragTexCoord)",
                {"baseline": "texture", "bilinear": "alphaBilinear", "cubic": "alphaCatmullRom"}[mode]
                + "(texture0, fragTexCoord)",
            )
            shader = rl.load_shader_from_memory(_ALPHA_TEST_VS_330, fragment)
            assert shader.id != rl.rl_get_shader_id_default()
            grounds[mode] = GroundRenderer(
                textures[0], textures[1], textures[0], terrain_filter=AlphaTestShader(shader=shader),
            )
            results[mode] = []
        for iteration in range(24):
            for mode in tuple(grounds)[iteration % 3:] + tuple(grounds)[:iteration % 3]:
                ground = grounds[mode]
                finish()
                start = time.perf_counter()
                ground.render_pristine(layers, target_size=(2048, 2048))
                rl.rl_draw_render_batch_active()
                finish()
                elapsed = (time.perf_counter() - start) * 1000
                if iteration >= 4:
                    results[mode].append(elapsed)
        print(json.dumps({
            "target": [2048, 2048], "stamps": 1700, "samples": 20,
            "timings": {
                mode: {"median_ms": statistics.median(samples), "p95_ms": sorted(samples)[18]}
                for mode, samples in results.items()
            },
        }, indent=2))
    finally:
        for ground in grounds.values():
            ground.close()
        for texture in textures:
            rl.unload_texture(texture)
        rl.close_window()


if __name__ == "__main__":
    main()
