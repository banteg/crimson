---
tags:
  - rewrite
  - rendering
  - modules
---

# RTX rendering

RTX is the Python port's alternative rendering mode. It combines analytic beam
shaders and wet ground materials with HDR world rendering and macOS extended dynamic range (EDR) output.
This page covers those paths, their controls, and how they differ from classic
rendering.

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
- if shader compilation/load is unavailable, rendering fails fast (runtime
  error) instead of silently falling back to classic
- Fire Bullets overlays and Ion chain behavior remain on the shared existing
  path

The analytic beam optimization covers streaks and heads while preserving
shared overlay and chain behavior. The HDR pass below applies to the whole world.


## RTX HDR world target and tonemapping

Implementation module: [`src/crimson/render/rtx/hdr.py`](https://github.com/banteg/crimson/blob/master/src/crimson/render/rtx/hdr.py).

When render mode is `rtx`, `WorldRuntime.draw()` wraps `draw_world()` in `HdrRenderer.scope()`:

- the world is drawn into a half-float (`RGBA16F`) framebuffer so additive passes (beams, plasma globes, fire particles, detonations, muzzle flashes) accumulate past `1.0` without 8-bit per-channel clipping
- pixels at or below the shoulder knee (`0.85`) pass through the tonemapper unchanged; the material pass below shades RTX terrain before this step
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

## Ground materials and wet blood

The Python RTX ground pass adapts the `crimson-night-argon` blood/material study,
without its blackout night lighting, flashlight cones, smoke pass, or separate
night mode. Unlit terrain retains approximately its classic brightness. Weapon
lights add modest diffuse illumination and source-colored specular reflections.
Classic continues to draw the original albedo target.

Implementation: `src/crimson/render/rtx/materials.py`, `material_shaders.py`, and
`material_lights.py`. The material target follows the albedo target's allocated
resolution and world coordinates, including texture scale and DPI:

- `RGBA32F`: specularity, blood deposit time in seconds, accumulated liquid volume,
  substrate height. Full precision avoids the study's four-minute clock saturation.
- `RGBA8`: ordered blood, corpse, and brass coverage. Later corpses cover old blood;
  later blood coats corpses again. Scorches remove gloss and ice uses a dielectric response.
- A separate clean substrate color target receives terrain, corpses, casings, ice,
  and scorches, but no blood RGB. Absorption therefore never re-tints the original
  blood-painted albedo. The latter stays intact for classic.
- Blood amount accumulates with screen blending; absorption recovers optical depth
  with `-log(1 - amount)` and an artistic scale. Deposits refresh the timestamp
  wherever their alpha passes the cutoff. Sampling takes the latest timestamp across
  the bilinear footprint so empty neighbors cannot make fresh edges old; the clock advances with presentation time,
  including slow motion, and pauses with the run.
- Diffuse normals come only from pristine terrain/corpse/casing height. Blood never
  adds a diffuse edge bevel. Separate liquid normals suppress fine dirt relief inside
  deep pools and add a filtered meniscus for reflections.
- Wet soil darkening, wavelength-dependent absorption, red subsurface color, and
  two specular lobes reproduce the study's smooth liquid appearance. Freshness decays
  exponentially with a 45-second time constant; this is gradual drying, not a switch
  at 45 seconds. These are artistic approximations, not calibrated optical constants.
- Up to 16 nearby energetic muzzle, Ion/Fire/Gauss/plasma, and detonation lights feed
  the ground pass. Beam lights use a tapered segment; the view vector is orthographic
  so moving the player does not drag the reflection viewpoint around the arena.
- Material color inputs are decoded from approximate gamma 2.2, shaded in linear
  RGB, and encoded back into the legacy compositor. Material output stays unclamped
  until the existing HDR shoulder. No extra material
  tonemapper, exposure reduction, or full-screen darkness is applied.

Companions and shaders allocate only on the first RTX draw. A CPU history of the
terrain's render batches supports switching to RTX after playing in classic. Replay
seeks restore that history from the existing preparation log, discard stale companions,
and rebuild lazily. New terrain and `RenderResources.close()` release the targets.
Presentation metadata carries deposit time; gameplay state, RNG consumption, replay
inputs, and native/browser rendering are unchanged.

### Remaining tradeoffs

- Ground illumination is currently unshadowed. A future visibility pass should gate
  each light's reflection individually, rather than multiply every light by the
  prototype's average shadow value. Entity lighting also needs to be tuned alongside
  terrain lighting while retaining a readable ambient floor.
- The strongest-16 selection can change abruptly in dense fights. Spatial clustering
  or temporal selection would improve continuity. Flame particles, chain arcs, and
  rocket exhaust are not independent ground emitters yet.
- Coverage, depth, and the latest timestamp are per pixel, not a multilayer fluid
  simulation. Small fresh deposits refresh old pools where they overlap. Drying,
  roughness, meniscus width, and blood absorption still need broader art tuning.
- The first RTX draw after a long classic session or a seek replays the material
  history synchronously and can hitch. This CPU history grows with terrain deposits.
  GPU companions and clean substrate cost 32 bytes per terrain pixel including the coverage target's
  depth attachment (32 MiB at 1024², 128 MiB at 2048²), including both RGBA8 targets' depth attachments.
  Packing channels, removing the unused depth attachment, and incremental reconstruction
  are worthwhile follow-ups.

A synchronized OpenGL comparison on an Apple M1 Pro at 960×540, using the Survival
fixture at ticks 4395/5115/6255 (30 warmed draws each), measured median whole-world
RTX draw times of 3.46/2.88/3.09 ms before materials and 3.94/3.21/3.70 ms with them.
These small samples include CPU submission and GPU completion, exclude simulation
and new decal bakes, and are not a general performance guarantee. The cold first draw
at tick 4395 replayed 369 batches in about 0.89 seconds. Continuous play normally
bakes only new deposits; late activation/seek latency remains a known limitation.

GPU tests cover ordered composition, depth accumulation, clocks beyond four minutes,
fresh/aged reflections above SDR white, unchanged diffuse height across blood borders,
actual ground-pass sampler binding, regeneration, and teardown. Replay tests verify
that backward seeks restore the corresponding deposit history and time.

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
enhancements (beam acceleration, HDR additive tonemapping, and EDR output now,
advanced lighting next), while keeping `classic` as the parity reference path.
