---
tags:
  - rewrite
  - rendering
---

# Terrain (rewrite)

This page describes how the **Python + raylib rewrite** models the classic game's
terrain pipeline (see also: `docs/crimsonland-exe/terrain.md`).

## Mental model

- The world background is a single **1024×1024 “ground” texture**.
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
- `GroundRenderer` maintains an internal RT sized from `1024/texture_scale`.
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
  `terrain_generate_random()`, or during quests `terrain_generate(&quest_selected_meta[minor * 10 + major])`
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

- Procedural terrain stamps keep bilinear sampling while rotating into the RT. The original engine appears to point-sample those stamps, but bilinear reads better in the port and still stays within current fixture tolerances.
- Corpse atlas frames keep bilinear sampling while baking for the same reason.

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
  - Scales positions/sizes by the allocated RT width divided by the terrain width. This includes the RT’s HiDPI scale and stays fixed if the window moves between monitors with different DPI.
  - Runs through the terrain alpha-test shim, so low-alpha fringe texels are discarded before blending.
  - Intentional rewrite deviation: generic decal sprites keep bilinear sampling while baking. The original engine appears to point-sample them, but bilinear reads better in the port.

- `GroundRenderer.bake_corpse_decals(bodyset_texture, [...])` for corpse sprites (bodyset 4×4 atlas frames).
  - Uses the same allocated RT scale as generic decals, so DPI changes preserve corpse positions and sizes.
  - Implements the two-pass corpse baking:
    - a “shadow/darken” pass using `ZERO / ONE_MINUS_SRC_ALPHA`
    - a normal alpha blend color pass
  - Applies the exe’s small alignment tweaks (`-0.5` shift and `offset = terrain_scale/512`) and rotation offset (`rotation - pi/2`).
  - Intentional rewrite deviation: corpse atlas frames keep bilinear sampling while baking. The original engine appears to point-sample them, but that looks worse in the port at modern output scales.

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
