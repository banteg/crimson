# `terrain_render`

Native target: `crimsonland.exe` at `0x004188a0` (693 bytes).

Live Binary Ninja evidence recovers the render-target fullscreen path, tiled
fallback path, camera UV calculation, and temporary renderer state changes.

Exact verified match: 100.00%, with 200/200 normalized instructions and
masked references `32/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- A `cv_terrainFilter` value of exactly `2.0` temporarily selects point
  filtering. Both render paths restore linear filtering afterward.
- With a valid render target, the function binds it, resets rotation and
  color, derives camera-relative UVs from the terrain dimensions, and draws a
  single fullscreen quad.
- The failed-render-target fallback disables alpha blending, batches a grid of
  256-by-256 quads over `(width / 256 + 1)` by `(height / 256 + 1)` tiles, and
  adds the camera offset to each integer tile position.
- The fallback uses guarded `do` loops, so its X/Y position accumulators are
  initialized only when the corresponding tile count is positive. Each inner
  iteration advances the tile counter before the X accumulator; that ordinary
  source order reproduces the final native VC6 register schedule.
- The fallback ends its batch and re-enables alpha blending before returning;
  the fullscreen path draws with the native scrolling UV window.

No inline assembly, volatile state, dummy references, or dead expressions are
used.
