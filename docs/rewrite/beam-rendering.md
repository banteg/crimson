---
tags:
  - rewrite
  - rendering
  - modules
---

# Beam rendering (classic + RTX)

This page documents the rewrite's current beam projectile rendering path and
the promoted RTX fast path for beam bodies and heads.

## Background: how the original renders beams

In the native executable, beam-like projectile types are handled in
`projectile_render` within the gameplay world render pass:

- world pass order reference: [`docs/crimsonland-exe/rendering.md`](../crimsonland-exe/rendering.md)
- beam-related projectile types and atlas mapping: [`docs/structs/projectile.md`](../structs/projectile.md)
- repeated-strip atlas/UV notes: [`docs/formats/atlas.md`](../formats/atlas.md)

The important behavior for these weapons is:

- beam body is built from repeated atlas samples along the shot vector
- rendering uses additive blending for the streak/head look
- beam head and special overlays (for example Fire Bullets glow and Ion chain
  behavior) are separate from the body strip stamping

That repeated-stamp body path is visually correct, but expensive in draw-call
count on long/high-density scenes.

## Rewrite classic path

Current classic implementation lives in
`src/crimson/render/projectile_draw/primary_beam.py`:

- `draw_beam_effect(...)` computes beam origin/head, segment range, and tint
- body rendering uses `_draw_beam_body_sprites(...)`, stamping atlas sprites
  across the beam span
- head/overlay behavior remains on the classic path
- Ion chain arcs and fade-stage core behavior stay in the shared beam draw path

This keeps parity-focused visuals as the baseline (`classic` mode).

## RTX fast body/head path

The promoted RTX implementation lives in `src/crimson/render/rtx/beam.py`:

- `draw_beam_fast_stamped_body(...)`
- `draw_beam_fast_stamped_head(...)`
- promoted from `beam_debug` `shader_stamped_virtual` under a production name
- draws oriented quads and evaluates "virtual stamps" analytically in a
  fragment shader, instead of issuing repeated sprite draws

Integration behavior:

- when render mode is `rtx`, beam body and head first attempt shader paths
- if shader compilation/load is unavailable, rendering falls back to classic
  texture body/head drawing
- Fire Bullets overlays and Ion chain behavior remain on the shared existing
  path

So the current RTX promotion is intentionally scoped to beam **streak/head**
acceleration while preserving established overlay/chain semantics.

## Render mode controls

Render mode enum and helpers: `src/crimson/render/rtx/mode.py` (`classic|rtx`).

Runtime/launch controls:

- launch flag: `--rtx` (game/net/lan entrypoints)
- console commands: `rendermode <classic|rtx>`, `togglertx`
- debug hotkey: `F4` toggles mode (debug builds)

Benchmark controls:

- render benchmarks can select mode via:
  - `uv run crimson replay benchmark <replay.crd> --mode render`
  - `uv run crimson replay benchmark <replay.crd> --mode render --rtx`
- telemetry/charts flow: [`docs/rewrite/deterministic-step-pipeline.md`](deterministic-step-pipeline.md)

## Observed perf shape (single-run example)

For the comparison run against
`survival_20260223_165511_score7046201.crd` (`runs=1`, `warmup_runs=0`), the
RTX beam path produced:

- strong draw-call reduction (median and tail)
- better mean/p95 frame and draw timing
- occasional larger worst-case spikes on isolated ticks

Treat this as directional evidence; final claims should use multi-run samples.

## Future direction

`crimson.render.rtx` is intended as the home for non-classic render
enhancements (beam acceleration now, advanced lighting next), while keeping
`classic` as the parity reference path.
