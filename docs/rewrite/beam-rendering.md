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
`src/crimson/render/world/projectiles.py`:

- `_draw_streak(...)`, called from `projectile_render`'s sprite pass, computes
  the streak's origin/head, segment range, and tint
- the body stamps atlas sprites across the streak's last 256 units
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
- RTX ion heads share their trails' blue tint; classic retains the original renderer's explicit warm head tint. This is an RTX visual adjustment, not a classified original bug.
- if shader compilation/load is unavailable, rendering fails fast (runtime
  error) instead of silently falling back to classic
- Fire Bullets overlays and Ion chain behavior remain on the shared existing
  path

So the current RTX promotion is intentionally scoped to beam **streak/head**
acceleration while preserving established overlay/chain semantics.


## RTX HDR world target and tonemapping

Implementation module: [`src/crimson/render/rtx/hdr.py`](https://github.com/banteg/crimson/blob/master/src/crimson/render/rtx/hdr.py).

When render mode is `rtx`, `WorldRuntime.draw()` wraps `draw_world()` in `HdrRenderer.scope()`:

- the world is drawn into a half-float (`RGBA16F`) framebuffer so additive passes (beams, plasma globes, fire particles, detonations, muzzle flashes) accumulate past `1.0` without 8-bit per-channel clipping
- pixels at or below the shoulder knee (`0.85`) pass through unchanged, keeping terrain, corpses, blood decals, and creatures identical to `classic`
- on SDR/8-bit targets, values above `0.85` compress the peak channel with a $C^1$ exponential shoulder while scaling the remaining channels proportionally to preserve hue, and stacks above `1.0` drift smoothly toward an incandescent white core (`white = 0.6` over a `3.0` excess span)
- selecting RTX always requests EDR; macOS uses a verified floating-point OpenGL backbuffer and Cocoa's `wantsExtendedDynamicRangeOpenGLSurface` opt-in, following [Apple's OpenGL EDR recipe](https://developer.apple.com/videos/play/wwdc2021/10161/)
- the Python window runner reserves a float surface for game windows so console/debug mode changes do not need to recreate the GL context; its temporary Cocoa pixel-format hook is restored immediately after window creation
- current display headroom is refreshed before each frame, including after display moves and fullscreen changes; potential headroom is not a rendering limit, and activation can ramp up from `1.0`
- the tonemapper approximates the legacy OpenGL transfer with gamma 2.2 and rolls highlights off toward current headroom; this is display-relative rendering, not a calibrated nit target
- gamma and letterbox targets preserve extended values; HUD, aim indicators, perk prompts, and console overlays are drawn outside the world tonemapper and remain in the SDR range
- returning to classic disables the Cocoa EDR opt-in and composites through an 8-bit target, preserving classic's per-draw saturation even on the reserved float window
- other platforms, unavailable float surfaces, and displays with headroom `1.0` use SDR tonemapping; an SDR ancestor target also forces SDR output for capture/compositing

This integration is limited to the Python port. The native/browser ports are unchanged.

In-game PNG screenshots still use an 8-bit SDR readback. Extended values clip to `1.0`, so screenshots do not preserve the brightness or highlight detail visible on an EDR display.

Run `uv run python scripts/experiments/edr_compare.py` on macOS for the two-window comparison using the same window setup. It checks the actual backbuffer format and float pixel readback; **E** toggles Cocoa EDR in the extended-range window. The patch labels are shader output components, not nits or linear-light ratios.

## Render mode controls

Render mode enum and helpers: `src/crimson/render/rtx/mode.py` (`classic|rtx`).

Runtime/launch controls:

- launch flag: `--rtx` (game entrypoint or `crimson replay play <replay.crd> --rtx`)
- console commands: `rendermode <classic|rtx>`, `togglertx`
- debug hotkey: `F4` toggles mode (debug builds)

Benchmark controls:

- render benchmarks can select mode via:
  - `uv run crimson replay benchmark <replay.crd> --mode render`
  - `uv run crimson replay benchmark <replay.crd> --mode render --rtx`

## Future direction

`crimson.render.rtx` is intended as the home for non-classic render
enhancements (beam acceleration and HDR additive tonemapping now, advanced
lighting next), while keeping `classic` as the parity reference path.
