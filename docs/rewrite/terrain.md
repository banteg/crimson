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

Implementation: `src/grim/terrain_render.py`

- `GroundRenderer` maintains an internal RT sized from `1024/texture_scale`.
- `GroundRenderer.schedule_generate(seed=...)` queues terrain generation, and `GroundRenderer.process_pending()` performs the scheduled RT creation/generation work.
- `GroundRenderer.draw(camera_x, camera_y)` draws the RT to the screen using UV scrolling.
- `texture_scale` is treated as a terrain-setup input, not a live runtime knob. Existing menu/gameplay grounds keep the scale they were created with until terrain is explicitly replaced.

Intentional rewrite deviations:

- Procedural terrain stamps keep bilinear sampling while rotating into the RT. The original engine appears to point-sample those stamps, but bilinear reads better in the port and still stays within current fixture tolerances.
- Corpse atlas frames keep bilinear sampling while baking for the same reason.

## Ground dump fixtures (parity test)

We captured **ground render-target dumps** via Frida and use the PNGs as
fixtures to ensure the rewrite matches within measured image tolerances for the same seed and
terrain texture indices.

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
  - Applies `inv_scale = 1/texture_scale` to positions/sizes so baked pixels match the exe’s scaled RT.
  - Runs through the terrain alpha-test shim, so low-alpha fringe texels are discarded before blending.
  - Intentional rewrite deviation: generic decal sprites keep bilinear sampling while baking. The original engine appears to point-sample them, but bilinear reads better in the port.

- `GroundRenderer.bake_corpse_decals(bodyset_texture, [...])` for corpse sprites (bodyset 4×4 atlas frames).
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
`src/crimson/world/terrain_runtime.py` applies terrain setup and generation requests. GPU calls do not run inside
the authoritative world step. See [run startup](replay-run-start.md#terrain-rng-and-rendering)
for detached terrain generation and RNG ownership.

The captured fixtures cover specific terrain configurations. Broader weapon,
bonus and corpse visual parity still needs corresponding runtime evidence.
