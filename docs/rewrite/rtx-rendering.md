---
tags:
  - rewrite
  - rendering
  - modules
---

# RTX rendering

RTX is the Python port's alternative rendering mode. It combines analytic beam
shaders, wet ground materials, and creature lighting with HDR world rendering and macOS extended dynamic range (EDR) output.
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

- `RGBA32F`: specularity, volume-weighted wetness, accumulated liquid volume,
  substrate height. Wetness uses a periodically rebased epoch to keep long-run
  calculations bounded.
- `RGBA8`: ordered blood, corpse, brass, and ice coverage in RGBA. Separate RGB/alpha
  blend factors let ice accumulate coverage while every later material occludes it.
  Normal `0.35`-alpha freeze shards receive an ice response without requiring repeated
  deposits. Ice occlusion is factored out when estimating the underlying film depth,
  preventing a shard from cutting a false liquid meniscus. Exposed ice retains the
  clean substrate/sprite color and its solid-surface reflection normal; blood deposited
  later reduces that ice coverage again. Later corpses cover old blood; later blood
  coats corpses again. Scorches remove gloss.
- A separate clean substrate color target receives terrain, corpses, casings, ice,
  and scorches, but no blood RGB. Absorption therefore never re-tints the original
  blood-painted albedo. The latter stays intact for classic.
- Blood volume accumulates with screen blending; absorption recovers optical depth
  from volume × coverage with `-log(1 - amount)` and an artistic scale. Wetness
  accumulates with the same blend weights as volume. Their filtered ratio keeps
  newly deposited thin spray fresh without letting it rejuvenate an entire old pool.
  Nonblood decals attenuate both channels equally, preserving the remaining blood's age.
  The clock follows presentation time, including slow motion, and pauses with the run.
- Diffuse normals come only from pristine terrain/corpse/casing height. Blood
  changes neither this normal nor its diffuse relief. Separate liquid normals suppress
  fine dirt relief inside deep pools and add a filtered meniscus from volume × coverage,
  rather than tracing thin spray outlines. `material_scope(debug=...)` exposes the
  shader's substrate normal (1), liquid normal (2), freshness (3), blood amount (4),
  and linear dynamic specular contribution (5).
- Fresh blood has a richer red body, including deep centers. The red body coefficient
  interpolates from `0.16` when fresh to `0.05` when aged; the deep-pool body weight
  similarly changes from `0.48` to `0.22`. A broad depth transition replaces the
  bright shallow band, and the gentler liquid slope avoids an embossed pool outline.
  Wet soil darkening and absorption still distinguish depth from age.
  Freshness decays exponentially with a 45-second time constant: about 37% remains
  at 45 seconds, 14% at 90 seconds, and 2% at 180 seconds. Color and reflections
  fade gradually; blood coverage remains. These are artistic controls, not
  calibrated optical constants.
- Up to 16 nearby energetic muzzle, Ion/Fire/Gauss/plasma, and detonation lights feed
  the ground pass, ranked around the actual view center rather than player one.
  A fixed orthographic virtual eye tilts backward by 30 degrees for specular only,
  placing reflections below their sources without moving the camera or dimming the arena.
  Moving players do not steer this viewpoint. The reflected eye ray intersects an
  emitter-height plane; distance to a finite tapered beam or point source determines
  the highlight. Roughness broadens and weakens its footprint instead of adding a
  broad second sheen lobe. Beam emitters sit at 40 world units; other sources retain
  their individual heights. Point-source blur spreads energy in two dimensions,
  degenerate segments fall back to points, and finite light support fades smoothly.
- Substrate color inputs are decoded from approximate gamma 2.2; emitter colors are
  already linear radiance, so lifetime gain stays linear. Shading is encoded once
  back into the legacy compositor. Material output stays unclamped
  until the existing HDR shoulder. No extra material
  tonemapper, exposure reduction, or full-screen darkness is applied.
- Ambient blood absorption uses a stable incidence. Each dynamic emitter computes
  its own transmission and diffuse relief before contributing radiance, so a faint
  light cannot darken the ambient film or recolor another emitter's contribution.
- Corpse/casing height is accumulated relief, `H′ = H + (1 − H) × height × alpha`,
  which raises the surface while retaining some terrain texture. It is not absolute
  replacement height; changing that appearance requires separate visual tuning.

Companions and shaders allocate only on the first RTX draw. Pending terrain bakes
are encoded into a temporary spool that spills to disk beyond 1 MiB, allowing a
late classic-to-RTX toggle without an unbounded Python object list. Applied batches
are discarded once their state resides on the GPU. Stamping runs pass-major in
bounded chunks, preserving each channel's decal order; cached uniforms and atlas-local
UVs allow consecutive blood quads to batch. Replay
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
- Coverage, depth, and weighted wetness are per pixel, not a multilayer fluid
  simulation. Drying, roughness, meniscus width, and blood absorption still need
  broader art tuning.
- The first RTX draw after a long classic session or a seek replays the material
  history synchronously and can hitch. Pending spool disk usage still grows with
  deposits until RTX consumes it, terrain resets, or the run closes.
  GPU companions and clean substrate cost 32 bytes per terrain pixel
  (32 MiB at 1024², 128 MiB at 2048²), including both RGBA8 targets' depth attachments.
  Packing channels, removing the unused depth attachment, and incremental reconstruction
  are worthwhile follow-ups.

A synchronized OpenGL comparison at `031f97307` on an Apple M1 Pro at 960×540, using the Survival
fixture at ticks 4395/5115/6255 (30 warmed draws each), measured median whole-world
RTX draw times of 3.95/3.59/3.53 ms before materials and 4.24/3.79/3.82 ms with them.
These small samples include CPU submission and GPU completion, exclude simulation
and new decal bakes, and are not a general performance guarantee.

A separate queued-bake benchmark used a 1024² terrain target inside a 960×540 target,
400 batches containing 4,934 mixed blood/casing/scorch/corpse stamps, and six synchronized
runs (first discarded). Pass-major stamping reduced the warm median from 1,568 ms
at `502e0994d` to 571 ms (2.7× faster). Initialization and queue encoding were outside
the timed region. Continuous play normally bakes only new deposits; first-activation
latency still depends on the accumulated backlog.

GPU tests cover ordered composition and equivalence between incremental and pass-major
bakes, actual shader normal outputs, thin/deep meniscus behavior, volume-weighted freshness
at ten hours, linear HDR emitter response, continuity at a fading light's boundary,
independent light contributions, backward reflection displacement, point/beam shape,
finite degenerate emitters, fresh/deep color and reflection aging, actual expired-shard ice response, ice-over-blood color
and depth, and blood-over-ice ordering,
clean substrate color, sampler binding,
regeneration, and teardown. CPU tests cover spool rollover/cleanup and view-centered
co-op light selection. Existing seek/reset lifecycle checks remain; RTX replay
optimization is deferred.

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

## Creature lighting

Python RTX creature bodies receive the same bounded weapon emitters as the ground
pass. A rounded body normal and weak texture relief provide broad colored lighting
and small highlights; three alpha taps toward each light produce an inner silhouette
rim. The approved blend uses 65% of the dome study and 65% of the rim study, with a
hue-preserving limit on their combined radiance, including thin-part transmission.
These are artistic shape estimates,
not authored normal maps or physically calibrated skin/chitin models.

Implementation: `src/crimson/render/rtx/creature_lighting.py` and
`creature_shaders.py`. Point emitters and finite beam segments both work in world
coordinates. The sprite basis is recovered from interpolated coordinates, so
rotation and size do not require per-creature uniform uploads or batch flushes.
Basis derivatives are evaluated before alpha discard, with an identity fallback
for singular UV mappings. Texture relief uses central differences at offsets of one atlas
texel, rotated into world space, so its strength does not depend on framebuffer
resolution. Both relief and alpha taps stay inside the current animation cell.
Lights are uploaded once before the species passes. Beam intensity tapers from
20% at the tail to 100% at the head; this gain applies once, independently of
squared radial attenuation. Point lights and the native alpha cutoff remain intact.

Thin parts also scatter lateral light, tinted by their pigment.
`src/crimson/render/rtx/creature_translucency.py` estimates part size from each
animation cell's alpha silhouette with the same alpha cutoff of 4/255.
It finds the largest fully contained odd square covering each pixel, capped at
31 texels. This is equivalent to accumulating nested square morphological openings:
erode, then dilate each surviving region back to its extent. Unlike boundary
distance, it assigns thick support to a broad body's edges as well as its center.
Descending max-dilation reconstructs all sixteen levels in fifteen steps; cells
remain isolated throughout.
Transmission falls as `exp(-0.48 * size)`, where size is the square's radius plus
one, with an artistic strength of 1.4. Its pigment multiplier is
`mix(vec3(0.15), baseLin, 0.85)`; even black parts retain a small 0.0225 floor.
The lateral response uses the light's elevation, independent of the cell-center
dome normal, so a narrow limb can scatter on either side of the sprite.
The shader samples this map once per body pixel and adds its directional response
inside the existing light loop, sharing each emitter's finite source, radial
attenuation and beam taper. It preserves sprite alpha and the existing HDR limit.
This is a silhouette part-size appearance model, not anatomical thickness or traced
subsurface scattering. Square openings are orientation-dependent and can still
classify curved tips and corners as thin. The model does not distinguish skin from
claws/armor, cast shadows, or account for intervening creatures.

Thickness textures are generated from the loaded source atlas on its first lit RTX
body pass, cached by that atlas's texture ID, and released when the world's lighting
resources close. Empty species and unlit/classic draws do not generate them.
Each 512×512 atlas adds a 256 KiB single-channel texture without mipmaps; generation
has a one-time readback and CPU preprocessing cost. Atlas binding happens once per
species body batch, with no per-creature texture uploads or additional render pass.

Only creature body passes use this shader. Existing shadows, hit flashes, freeze
and poison overlays, players, and baked corpses keep their existing paths. No
additional ambient darkening or cast shadows are introduced. Classic bypasses
lighting entirely; an empty light list also uses the original body shader. GPU
resources are lazy and released with the world's render resources. The existing
HDR world target and display shoulder handle the added highlights.

## Bonus materials

Python RTX replaces the pickup bubble bitmap with an analytical dark sphere and
lights the original bonus and weapon icon artwork as a shallow foil/enamel emblem.
The Argon bonus study supplies the visual baseline: a black core, the original
top-right studio highlight, directional edge crescents, and curved reflections of
finite weapon beams. The opposite-wall glow suggests internal refraction; these
are artistic material approximations, not a calibrated glass simulation.

Implementation: `src/crimson/render/rtx/bonus_lighting.py` and `bonus_shaders.py`.
The shell and emblem share a coating normal derived from the pickup's fixed world
center and radius. Icon pulsing, rotation, and weapon aspect ratio cannot move or
stretch that coating. Weapon portions outside the shell retain their surface and
edge lighting without a spherical reflection. Texture-relief and edge probes stay
inside their bonus/weapon atlas cell, and derivatives precede alpha discard.

The renderer retains the original bubble/icon draw order, icon animation, spawn
fades, expiration blink, and weapon fade. It uploads the bounded weapon lights
once per pickup pass and flushes before changing each draw's material/center
uniforms; the pool is bounded to 16 entries. The shader is created only when RTX
draws an occupied pool, and is released by the world's render resources.
Classic uses its original bitmap path. Unlit RTX emblems retain their source
colors; the analytical shell retains its studio highlight.
