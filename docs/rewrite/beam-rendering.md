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

- when render mode is `rtx`, beam body and head use the promoted shader paths
- if shader compilation/load is unavailable, rendering fails fast (runtime
  error) instead of silently falling back to classic
- Fire Bullets overlays and Ion chain behavior remain on the shared existing
  path

So the current RTX promotion is intentionally scoped to beam **streak/head**
acceleration while preserving established overlay/chain semantics.

## Render mode controls

Render mode enum and helpers: `src/crimson/render/rtx/mode.py` (`classic|rtx`).

Runtime/launch controls:

- launch flag: `--rtx` (game entrypoint)
- console commands: `rendermode <classic|rtx>`, `togglertx`
- debug hotkey: `F4` toggles mode (debug builds)

Benchmark controls:

- render benchmarks can select mode via:
  - `uv run crimson replay benchmark <replay.crd> --mode render`
  - `uv run crimson replay benchmark <replay.crd> --mode render --rtx`
- telemetry/charts flow: [`docs/rewrite/deterministic-step-pipeline.md`](deterministic-step-pipeline.md)

## Observed benchmark results (single-run sample)

Replay benchmark run:

- replay: `survival_20260223_165511_score7046201.crd`
- sampling: `runs=1`, `warmup_runs=0`
- artifacts: `bench/render_cmp_20260223_170207/`

Primary p50 metrics from `summary.txt`:

| Metric | Classic | RTX | Delta (RTX - Classic) |
| --- | ---: | ---: | ---: |
| `wall_ms_p50` | `2387199.955` | `1778650.386` | `-608549.569` |
| `tps_p50` | `33.16` | `44.51` | `+11.35` |
| `realtime_x_p50` | `0.39` | `0.53` | `+0.14` |
| `frame_ms_p50` | `21.284` | `20.089` | `-1.195` |
| `draw_ms_p50` | `17.974` | `18.174` | `+0.201` |
| `draw_calls_p50` | `1280.00` | `524.00` | `-756.00` |

Additional telemetry from run stdout:

- draw calls:
  - mean: `2130.22 -> 789.21`
  - p95: `5386.95 -> 1959.00`
  - max: `8275 -> 3480`
- frame timing:
  - p95: `62.003 ms -> 49.429 ms`
  - max: `96.519 ms -> 160.531 ms`
- draw timing:
  - p95: `58.900 ms -> 43.120 ms`
  - max: `93.920 ms -> 156.601 ms`

Interpretation for this sample: RTX materially reduces draw calls and improves
overall throughput/frame distribution, while showing larger rare worst-case
spikes. For release-facing claims, re-run as a multi-sample benchmark.

## Future direction

`crimson.render.rtx` is intended as the home for non-classic render
enhancements (beam acceleration now, advanced lighting next), while keeping
`classic` as the parity reference path.
