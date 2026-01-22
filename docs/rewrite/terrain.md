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

Implementation: `src/crimson/terrain_render.py`

- `GroundRenderer.create_render_target()` creates/resizes the RT (`1024/texture_scale`).
- `GroundRenderer.generate(seed=...)` stamps the 3 procedural layers into the RT.
- `GroundRenderer.draw(camera_x, camera_y)` draws the RT to the screen using UV scrolling.

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

## Terrain filter (“terrainFilter”)

The exe optionally forces point sampling when blitting terrain to the screen if
`terrainFilter == 2.0`.

The rewrite mirrors this via `GroundRenderer.terrain_filter`:

- `terrain_filter == 2.0` → temporary point sampling for the terrain blit only.

## Next step

For visual verification, the `ground` debug view can now bake blood decals into
the terrain render target (left click to stamp).

Remaining gaps for parity:

- A real producer for terrain decal events (queueing from gameplay/effects).
- Calling the baking pass in the correct place in the main render order (exe:
  `fx_queue_render` before `terrain_render`).
