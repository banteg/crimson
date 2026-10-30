---
tags:
  - rewrite
  - rendering
---

# Terrain (rewrite)

This page describes how the **Python + raylib rewrite** models the classic game's
terrain pipeline (see also: `docs/crimsonland-exe/terrain.md`).

## Mental model

- The world background covers **1024×1024 logical units**. Interactive clients bake it at 2× density (2048×2048 pixels by default).
- In the original exe, it is a **render target** that gets:
  1) procedurally generated once (`terrain_generate`)
  2) incrementally updated by **baking decals** (blood/corpses/etc) into the same texture (`fx_queue_render`)
  3) drawn to the screen as **one fullscreen quad** with UV scrolling based on camera offsets (`terrain_render`)

## Where this lives in the rewrite

Generation: `src/crimson/sim/terrain_generate.py`; drawing: `src/grim/terrain_render.py`

- `terrain_generate(rng, slots)` and `terrain_generate_random(rng, unlock_index)` mirror the two native
  functions. They consume the authoritative `crt_rand` stream eagerly and return a `TerrainSetup`: the
  texture slots plus three stamp layers (`grim.terrain_stamps.TerrainLayers`). Each stamp is the native
  pre-scale value: float32 rotation `(float)(rand % 314) * 0.01f`, and a top-left `rand % 1152 - 64`
  that already includes the overscan, drawn rotation, then y, then x.
- `GroundRenderer` maintains an internal RT sized from `2048/texture_scale`, independent of window DPI.
- `GroundRenderer.schedule_stamps(layers, texture_scale=...)` queues drawing a generated setup, and `GroundRenderer.process_pending()`
  performs the scheduled RT creation and stamping. It applies `inv_scale`, moves the native top-left to
  raylib's quad center, and never touches an RNG, so drawing or re-applying a setup is free.
- `GroundRenderer.draw_view(camera, screen_w=..., screen_h=..., out_w=..., out_h=...)` draws the RT to the screen using UV scrolling.
- `texture_scale` is a terrain-setup input, not a live runtime knob: it is passed with the stamps and only sizes the RT. Existing menu/gameplay grounds keep their RT until terrain is explicitly replaced, and every draw into it reads the scale back from the allocated RT.

A ground only changes when a setup is applied: gameplay and replay playback install `PreparedRun.terrain`,
menus draw their own `terrain_generate_random` on the application stream (or keep the gameplay ground
they took over), and the arsenal and lighting debug views apply a detached terrain on each scene reset.
Resetting the world or reopening render resources leaves the ground alone.

### Generation scope

- The simulation assumes the terrain texture never fails (`terrain_texture_failed == 0`), as it assumes audio
  is on. Natively a failed texture makes `terrain_generate` bind the descriptor's base texture and return
  before any stamp draw, while `terrain_generate_random` still draws its three selector draws and the eligible
  unlock rolls: a successful roll delegates to that draw-free fallback, and the default branch returns
  without stamping. A capture from such a run would need that flag recorded in its run metadata.
- Native recovery regeneration is not modelled. When Grim sets config var `0x57` (texture backup failure,
  DC-mode `WM_PAINT`), `game_frame_update` regenerates terrain mid-run on the live stream:
  `terrain_generate_random()`, or during quests `terrain_generate(&quest_meta_table[minor * 10 + major])`
  with minor and major wrapped separately, a swapped index that can read past the 50-entry table (quest 1.6
  gives 50). A capture containing it cannot replay exactly. Should the port ever rebuild a lost render
  target, it would redraw the retained setup rather than draw new terrain.
- The console `generateterrain` command natively runs `terrain_generate_random()` on the live stream. The
  port keeps the gameplay RNG and the current texture slots, and stamps with `terrain_generate` from a
  detached `Crand` seeded from the gameplay RNG state plus a counter that advances per command. The menu
  ground regenerates with `terrain_generate_random` on the application stream.
- Demo/attract terrain (`demo_setup_variant_1`/`_3` and the reset inside `demo_mode_start`) is excluded
  with the rest of attract mode.

Intentional rewrite deviations:

- Procedural terrain stamps use Catmull–Rom reconstruction in premultiplied-alpha space while rotating into the RT. Negative-lobe overshoot is clamped before converting back to straight alpha for the existing blend equations.
- Decals, corpse atlas frames and bilinear-filtered artwork reconstruct in premultiplied-alpha space with four source samples. This prevents invisible RGB from tinting or darkening translucent edges. Source uploads stay RGBA8; no extra source textures are allocated.
- The shared shader is `src/grim/filtering.glsl`. Python includes it in artwork shaders; the native/WebGL renderer uses it for linearly filtered source artwork. Cubic reconstruction is restricted to terrain artwork baked into a target. Point sampling, render-target copies, ground presentation, fonts, analytical effects and the alpha cutoff remain unchanged.

## Ground dump fixtures (parity test)

**Ground render-target dumps** captured from the original game (with the
since-removed Frida tooling, so they cannot be regenerated) serve as fixtures
to ensure the rewrite matches within measured image tolerances for the same
seed and terrain texture indices.

- Fixtures: `tests/fixtures/ground/ground_dump_*.png` + `tests/fixtures/ground/ground_dump_cases.json`
- Test: `tests/render/test_ground_dump_fixtures.py`

Run the test:

```bash
uv run pytest tests/render/test_ground_dump_fixtures.py --run-terrain
```

Notes:

- Requires a display accessible to raylib. On macOS, a sandbox can hide the
  active display; run these tests with display access. Linux checks `DISPLAY`
  / `WAYLAND_DISPLAY`.
- Requires game assets at `game_bins/crimsonland/1.9.93-gog/crimson.paq`.
- The test renders at the capture's pixel dimensions, including on Retina
  displays. Missing tracked captures fail the test instead of skipping it.
- `tests/render/test_shader_pixels.py` checks the alpha cutoff, shader cleanup,
  and full-frame gamma with GPU pixel readback. It needs a display but no game
  assets or `--run-terrain` flag.

## Decal baking

The exe’s “persistent gore” works because it is drawn **into the ground render
target** before terrain is blitted to the backbuffer.

The rewrite exposes the same mechanism via two helpers:

- `GroundRenderer.bake_decals([...])` for generic textured decals (blood, scorch, etc).
  - Scales positions/sizes by the allocated RT width divided by the terrain width. This includes the RT’s fixed 2× density and stays fixed if the window moves between monitors with different DPI.
  - Runs through the terrain alpha-test shim, so low-alpha fringe texels are discarded before blending.
  - Uses bilinear reconstruction in premultiplied-alpha space while baking.

- `GroundRenderer.bake_corpse_decals(bodyset_texture, [...])` for corpse sprites (bodyset 4×4 atlas frames).
  - Uses the same allocated RT scale as generic decals, so DPI changes preserve corpse positions and sizes.
  - Implements the two-pass corpse baking:
    - a “shadow/darken” pass using `ZERO / ONE_MINUS_SRC_ALPHA`
    - a normal alpha blend color pass
  - Applies the exe’s small alignment tweaks (`-0.5` shift and `offset = terrain_scale/512`) and rotation offset (`rotation - pi/2`).
  - Uses the same bilinear reconstruction in premultiplied-alpha space.

## Blend mode when drawing to screen

During terrain generation, stamps are drawn with alpha blending enabled
(`SRC_ALPHA / ONE_MINUS_SRC_ALPHA`). On an RGBA render target, this affects not
just RGB, but also the **alpha channel**:

```
result_alpha = src_alpha * src_alpha + dst_alpha * (1 - src_alpha)
```

In the original exe, the `"ground"` render target is typically created in an
XRGB format (no alpha), so this drift never matters. In the rewrite, the RT is
RGBA, so we emulate XRGB more directly by **masking out alpha writes** while
stamping into the terrain RT:

```python
rl.rl_color_mask(True, True, True, False)
rl.rl_set_blend_factors(rl.RL_SRC_ALPHA, rl.RL_ONE_MINUS_SRC_ALPHA, rl.RL_FUNC_ADD)
rl.begin_blend_mode(rl.BLEND_CUSTOM)
# On some backends, re-apply factors after switching the mode.
rl.rl_set_blend_factors(rl.RL_SRC_ALPHA, rl.RL_ONE_MINUS_SRC_ALPHA, rl.RL_FUNC_ADD)
# ... stamp decals/strokes into the RT ...
rl.end_blend_mode()
rl.rl_color_mask(True, True, True, True)
```

Additionally, when drawing the terrain RT to the screen, we use a custom blend
mode that fully replaces pixels (ignoring source alpha):

```python
rl.rl_set_blend_factors(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD)
rl.begin_blend_mode(rl.BLEND_CUSTOM)
# On some backends, re-apply factors after switching the mode.
rl.rl_set_blend_factors(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD)
# ... draw terrain quad ...
rl.end_blend_mode()
```

This ensures terrain is always drawn opaque, matching the original game's behavior.

Why this mode:

- It keeps the terrain RT alpha pinned to `255` through generation and baking, which matches the XRGB mental model directly.
- It is simpler than carrying separate blend-factor branches for alternate alpha behaviors that we do not intend to ship.

## Runtime application

Simulation collects generic and corpse decals in `src/crimson/sim/terrain_fx.py`.
The session captures each tick's batch in its presentation plan;
`src/crimson/sim/batch_apply.py` delivers it to
`src/crimson/world/render_resources.py` for baking.
`WorldRuntime.apply_terrain_setup` (`src/crimson/world/runtime.py`) installs a `TerrainSetup` and remembers it. GPU calls do not run inside
the authoritative world step. See [run startup](replay-run-start.md#terrain-rng-and-rendering)
for terrain generation and RNG ownership.

The captured fixtures cover specific terrain configurations. Broader weapon,
bonus and corpse visual parity still needs corresponding runtime evidence.

## Replay memory

Both interactive clients retain at most eight checkpoints in either mode, preserving
the original seek spacing. Classic color checkpoints cost 128 MiB; RTX's clean
initial color target (16 MiB) and seven material snapshots (112 MiB each) cost
800 MiB at the default 2048×2048 size. Each RTX
snapshot preserves color, substrate and coverage as RGBA8, surface as RGBA32F
(or the WebGPU device's half-float surface format), and the wetness epoch.
These figures exclude other render targets; nondefault terrain sizes change the
cost. Compaction frees old snapshots before allocating replacements and doubles
the spacing. Copies retain the full 2× resolution, avoiding cumulative blur on
restoration. Native reconstruction batches material draws across logged bakes to
reduce framebuffer switching. Disk snapshots are already losslessly zstd-compressed;
resident GPU snapshots remain uncompressed.

Backend simulation allocates no ground framebuffer. Server replay thumbnails
retain their existing 1× software rasterizer; this change does not alter that path.

## Filtering cost

Measured on Apple M1 Pro, 2026-10-20, with a 2048×2048 target in every variant.
Times include CPU submission and synchronized GPU completion, excluding shader
compilation, asset loading and initial allocation. Each result has four warmups
and 20 samples. These are workload timings, not whole-game FPS or isolated GPU
kernel timings. Raw results are in `crimson-core/results/ground_filtering.json`.

| Workload | Ordinary bilinear | Associated bilinear | Associated Catmull–Rom |
| --- | ---: | ---: | ---: |
| Python Q1 terrain, 1,700 real asset stamps | 3.71 ms | 6.70 ms | 20.37 ms |
| Native renderer, 1,700 synthetic terrain stamps | 13.55 ms | 16.58 ms | 30.09 ms |
| WebGL2 renderer, same synthetic terrain | 12.00 ms | 17.50 ms | 31.00 ms |

Cubic adds about 17–19 ms to these terrain rebuilds. It runs when constructing
terrain, not when presenting each frame or baking later blood/corpses. Python's
real-asset workload and the C++ synthetic workload have different coverage and
submission paths, so their absolute times should not be compared directly.

The separate 500-sprite synthetic workload uses associated bilinear in both new
modes: native median 1.12 ms before versus 1.13–1.21 ms after; WebGL2 1.41 ms before
versus 1.66–2.13 ms after. Browser scheduling/timer noise is visible even between
identical sprite shaders. Each sprite sample averages 16 synchronized frames;
these figures do not predict an equivalent whole-game frame-time increase.

Reproduce (GPU/display required):

```sh
uv run scripts/bench_ground_filtering.py --paq /path/to/crimson.paq
uv run crimson-core/checks/renderer.py --benchmark baseline
uv run crimson-core/checks/renderer.py --benchmark bilinear
uv run crimson-core/checks/renderer.py --benchmark cubic
# Add --web to build each workload for WebGL2; serve crimson-core/build
# and open renderer-check-{baseline,bilinear,cubic}/index.html.
```

The Python benchmark interleaves the three modes using Q1 terrain and seed
`0xC0FFEE`. The native/WebGL benchmark uses deterministic synthetic RGBA artwork,
1,700 rotated overlapping terrain stamps, and a separate 500-quad sprite pass.
It runs the production renderer's pixel regressions before timing.

### Snapshot compression investigation

On the 30,000-tick survival fixture, two complete 112 MiB snapshots compressed
losslessly with zstd level 1 to 36.6 and 39.7 MiB. Warm CPU compression took about
213 ms and decompression 94–97 ms. The production OpenGL snapshot readback took
6.4 ms and upload/restoration 17.7 ms (medians after the first use, exact bytes
verified). Fast zstd level -5 reduced the later snapshot to 57.1 MiB and decoded
in 55.2 ms; GPU upload would still add about 17.7 ms. Disk snapshots already use
zstd, but moving resident snapshots to compressed CPU storage would add this work
to a cold seek. These are machine-specific timings, not browser measurements.
See [raw measurements](../../crimson-core/results/replay_material_compression.json).

GPU block compression is possible for immutable snapshots, but needs an encoder
and a shader restore into the writable planes. It cannot replace the existing
blits directly: [WebGPU texture copies require copy-compatible formats](https://www.w3.org/TR/webgpu/#copy-compatible),
and [compressed formats are not render attachments](https://www.w3.org/TR/webgpu/#compressed-formats).
BC7 stores normalized RGBA, while BC6H stores HDR RGB without the surface's height
channel; neither directly preserves the four floating-point material channels.
See the [BPTC format specification](https://registry.khronos.org/OpenGL/extensions/ARB/ARB_texture_compression_bptc.txt).
The measured surface's wetness channel reached 9.17, beyond normalized color.

An RGBA16F surface would lower the eight-checkpoint budget from 800 to 576 MiB.
A CPU quantization probe changed 61.7% of the surface floats, with maximum absolute
channel errors of 0.000122, 0.003906, 0.000244 and 0.000244. This is a possible
separate visual-quality experiment, not a lossless replacement. The current fix
keeps exact full-resolution material planes and the original eight-copy spacing.
