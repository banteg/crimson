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

- `GroundRenderer.create_render_target()` creates/resizes the RT (`1024/texture_scale`).
- `GroundRenderer.generate(seed=...)` stamps the 3 procedural layers into the RT.
- `GroundRenderer.draw(camera_x, camera_y)` draws the RT to the screen using UV scrolling.

## Ground dump fixtures (parity test)

We captured **ground render-target dumps** via Frida and use the PNGs as
fixtures to ensure the rewrite produces identical output for the same seed and
terrain texture indices.

- Fixtures: `tests/fixtures/ground/ground_dump_*.png` + `tests/fixtures/ground/ground_dump_cases.json`
- Test: `tests/test_ground_dump_fixtures.py`

Run the test:

```bash
uv run pytest tests/test_ground_dump_fixtures.py
```

Notes:

- Requires a display (raylib); the test skips if `DISPLAY` / `WAYLAND_DISPLAY` is missing.
- Requires game assets at `game_bins/crimsonland/1.9.93-gog/crimson.paq`.

## Decal baking (what was missing)

The exe’s “persistent gore” works because it is drawn **into the ground render
target** before terrain is blitted to the backbuffer.

The rewrite exposes the same mechanism via two helpers:

- `GroundRenderer.bake_decals([...])` for generic textured decals (blood, scorch, etc).
  - Applies `inv_scale = 1/texture_scale` to positions/sizes so baked pixels match the exe’s scaled RT.
  - Uses point filtering while stamping (matches the exe’s `filter=1` during baking).

- `GroundRenderer.bake_corpse_decals(bodyset_texture, [...])` for corpse sprites (bodyset 4×4 atlas frames).
  - Implements the two-pass corpse baking:
    - a “shadow/darken” pass using `ZERO / ONE_MINUS_SRC_ALPHA`
    - a normal alpha blend color pass
  - Applies the exe’s small alignment tweaks (`-0.5` shift and `offset = terrain_scale/512`) and rotation offset (`rotation - pi/2`).

## Terrain filter ("terrainFilter")

The exe optionally forces point sampling when blitting terrain to the screen if
`terrainFilter == 2.0`.

The rewrite mirrors this via `GroundRenderer.terrain_filter`:

- `terrain_filter == 2.0` → temporary point sampling for the terrain blit only.

## Blend mode when drawing to screen

During terrain generation, stamps are drawn with alpha blending enabled
(`SRC_ALPHA / ONE_MINUS_SRC_ALPHA`). On an RGBA render target, this affects not
just RGB, but also the **alpha channel**:

```
result_alpha = src_alpha * src_alpha + dst_alpha * (1 - src_alpha)
```

In the original exe, the `"ground"` render target is typically created in an
XRGB format (no alpha), so this drift never matters. In the rewrite, the RT is
RGBA, so we ensure the ground RT alpha stays at 1.0 by **preserving destination
alpha** while stamping:

```python
rl.begin_blend_mode(rl.BLEND_CUSTOM_SEPARATE)
rl.rl_set_blend_factors_separate(
    rl.RL_SRC_ALPHA, rl.RL_ONE_MINUS_SRC_ALPHA,  # RGB
    rl.RL_ZERO, rl.RL_ONE,                       # A (keep dst alpha)
    rl.RL_FUNC_ADD, rl.RL_FUNC_ADD,
)
# ... stamp decals/strokes into the RT ...
rl.end_blend_mode()
```

Additionally, when drawing the terrain RT to the screen, we use a custom blend
mode that fully replaces pixels (ignoring source alpha):

```python
rl.begin_blend_mode(rl.BLEND_CUSTOM)
rl.rl_set_blend_factors(rl.RL_ONE, rl.RL_ZERO, rl.RL_FUNC_ADD)
# ... draw terrain quad ...
rl.end_blend_mode()
```

This ensures terrain is always drawn opaque, matching the original game's behavior.

## Current status

- Gameplay produces decal events through `FxQueue` / `FxQueueRotated` (projectile hits and creature deaths) in `src/crimson/game_world.py`.
- `GameWorld.update()` bakes queued decals into the ground render target via `bake_fx_queues(...)`; the result is then shown when `GroundRenderer.draw(...)` blits the RT to the screen.
- The `ground` debug view is still useful for manual stamping when validating blend/filter behavior.

## Remaining gaps

- Validate effect selection, sizes, and tints against runtime captures for a wider set of weapons/bonuses.
- Expand decal producers beyond the current hit/death hooks as more gameplay effects are ported.
