# `load_textures_step`

Native target: `crimsonland.exe` at `0x0042abd0` (1203 bytes).

Live Binary Ninja evidence recovers the complete ten-stage texture-loading
schedule used by `game_startup_init`, including the terrain safe-mode fork,
published texture handles, and terminal startup latch.

Exact verified match: 100.00%, with 252/252 normalized instructions and
masked references `209/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The routine is a sequence of ten independent stage checks, not a switch.
  Every invocation performs the current stage, increments the stage counter,
  publishes the total value 11, flushes `console.log`, and returns whether the
  terminal sentinel has been reached.
- Stages 0 through 4 load creature, projectile, UI-control, particle, and HUD
  resources. Returned handles are published only for native consumers that
  need direct access; several cache-warming calls intentionally discard them.
- Stage 5 loads eight normal terrain layers or four fallback quadrants. The
  fallback path also makes its first quadrant the terrain render target.
- Stages 6 through 8 load quest text/digits, weapon and clock UI, muzzle/drop
  assets, and resolve the `ground` render target outside safe mode.
- Stage 9 moves the game to the main-menu state, resolves the cached
  `bullet_i` and legacy `aim64` handles, and raises the bootstrap-pending latch
  consumed by `game_startup_init`.

Live xrefs show the `aim64` handle has no surviving native reader, while the
stage-count global is rendered as `value - 1` in the startup progress text.
