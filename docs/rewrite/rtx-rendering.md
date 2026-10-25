---
tags:
  - rewrite
  - rendering
  - modules
---

# RTX rendering

RTX is the Python port's alternative rendering mode. It combines analytic beam
shaders, wet ground materials, and creature lighting with HDR world rendering and extended dynamic range (EDR) output on macOS and Wayland.
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
- on Wayland, the window gets an RGBA16F EGL surface where the driver and compositor share a float format, else a 10-bit one, and is tagged through `wp_color_management_v1` as gamma 2.2 sRGB whose signal `1.0` is the display peak and whose reference white is the compositor's; the canvas divides the frame by the shoulder's limit (`headroom^(1/2.2)`) so SDR white lands on the reference level. Headroom is the preferred description's target peak over its reference white, refreshed when the compositor reports a new preferred description (another output, HDR toggled). Compositors without parametric descriptions, `set_luminances` or gamma 2.2, and X11 sessions, stay SDR
- the Python window runner reserves a deep surface for game windows so console/debug mode changes do not need to recreate the GL context; its temporary pixel-format hook (Cocoa) or EGL config filter (Wayland) is removed immediately after window creation
- current display headroom is refreshed before each frame, including after display moves and fullscreen changes; potential headroom is not a rendering limit, and activation can ramp up from `1.0`
- the tonemapper approximates the legacy OpenGL transfer with gamma 2.2 and rolls highlights off toward current headroom; this is display-relative rendering, not a calibrated nit target
- gamma and letterbox targets preserve extended values; HUD, aim indicators, perk prompts, and console overlays are drawn outside the world tonemapper and remain in the SDR range
- returning to classic disables the Cocoa EDR opt-in or unsets the Wayland image description and composites through an 8-bit target, preserving classic's per-draw saturation even on the reserved deep window
- Windows, unavailable deep surfaces, and displays with headroom `1.0` use SDR tonemapping; an SDR ancestor target also forces SDR output for capture/compositing

The native and browser clients run the same HDR world target and tonemap (see [Native client](#native-client)
and [Browser client](#browser-client)).

In-game PNG screenshots still use an 8-bit SDR readback, taken from the frame before Wayland's presentation scaling. Extended values clip to `1.0`, so screenshots do not preserve the brightness or highlight detail visible on an EDR display.

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
- Independently bounded illumination and reflection sources feed the ground pass,
  ranked around the actual view center rather than player one (see weapon profiles below).
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
- Flame particles are grouped spatially, and a flame cell's light can still jump
  as the stream crosses cell boundaries.
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
- replay videos render RTX too, tonemapped for SDR:
  `uv run crimson replay render <replay.crd> --rtx` (`--no-rtx-smoke` without the fluid smoke)

### Golden scenes

`tools/rtx/scenes.toml` names replay moments that exercise each RTX path:
- aged blood with almost no light
- frozen creatures, and fire across ice
- rocket smoke
- the nuke
- ion beams through smoke
- dense beam lights
- a Shock Chain crowd

`uv run python tools/rtx/golden.py capture --game <game folder> --out <dir>` captures each one, classic and RTX, with
the native client. The client seeks a little before the tick, pauses on it (`CRIMSON_CAPTURE_TICK`) and records the
median GPU time per pass over the frames leading to it (`CRIMSON_GPU_TIMERS`). `golden.py compare <before> <after>`
puts two captures side by side with a difference map, the mean change and the GPU time per scene. Captures tonemap
for SDR, so they read the same on any display.

## Native client

The native client (`crimson-core/client`) shows RTX through the same GLSL as the
Python port: `src/crimson/render/rtx/shaders/*.frag` are loaded by Python and built
into the client's `rtx_shaders.h` (`crimson-core/client/shaders.py`). The client
renders the original game, so it cannot branch inside a Python draw path; instead
the game module marks where the world starts and ends in a frame
(`crimson-core/game/rtx/rtx.patch`, `game/rtx.cpp`), and the host
(`client/renderer.cpp`) draws the world between those marks into an `RGBA16F`
target, tonemaps it onto a half-float back buffer, and draws the HUD over it.
Classic keeps its 8-bit back buffer, so each classic draw still saturates at white.
Creature bodies and players are lit as in the Python port, with the same
`creature.frag` and `player.frag` (moved into `shaders/` with the shared
`source_geometry.glsl` and `light_visibility.glsl`). The game module collects
the frame's lights at the world's start (`crimson-core/game/rtx_lights.cpp`, a
port of `material_lights.py`): projectiles and their ion arcs, muzzle flashes,
the Sharpshooter sight, the Radioactive aura, rocket exhaust, detonations and
grouped flame particles, and explosion fireballs and shells, with the same
idents, volley merging and per-response selection and fades (on `run_elapsed_ms`,
reset with the run), and draws the ion arcs' contact glows in their own pass
(`HOST_PASS_GLOW`) as the creatures begin. Like `ExplosionVisual`, the module records each explosion
burst as it spawns: its fireball sprites as they start out, and whether its ring
spawned. Rocket hits stay dark, their detonation lighting them instead. The
records age with the effects' update and are kept apart from the run. A freed slot
leaves its record (`effect_free`), so a reused slot is never mistaken for one.
The records also draw the explosion as `draw_effect_pool` does in RTX:
- the explosion's own ring becomes the warm shell (the RING cell tinted
  `(190, 163, 122)` at the shell's radius and alpha); a rocket's ring isn't drawn
- a lit explosion's fireballs are drawn from how they spawned, at half speed
  (1.4 s), in place of their native slots

Each frame the module sends the shells as pressure fronts (`host_pressure`, at
most 16). Before the tonemap, the host displaces the world through
`pressure.frag` into a second HDR target. The client's targets run v down, so
`client/shaders/pressure_lit.frag` defines `TARGET_V_DOWN`. The module marks the creature body and player batches
(`HOST_PASS_CREATURES`, `HOST_PASS_PLAYERS`), and the host draws them with the
lit programs, the camera offset giving each fragment its world position.
Creature bodies keep the 0.60 ambient fill even without lights; players keep
the device's shading until lit. Thin-part transmission uses the same
part-size map (`crimson-core/client/thickness.cpp`, a port of
`creature_translucency.py`), made from the atlas texels the module keeps on a
creature atlas's first lit draw. Creature shadows use the same body grid
(`rtx_build_occlusion`, a port of `reflection_occlusion.py`): the module builds
it from the creature pool against the selected lights and sends it each frame
(`host_occlusion`, crowd cells included), and the hosts upload it as the RGBA32F texture the shader
walks (unfilterable in WebGPU, which reads it with `textureLoad` alone). The
shadows setting turns direct-light visibility off as in the Python port.
Bonuses take the same `bonus.frag`: the module marks each shell, icon and
weapon icon quad (`host_bonus`, with its atlas grid and the bonus's position as
the shell center), and the host draws it with the bonus program whether or not
lights reach it, as `draw_bonus_pickups` does.

The ground takes the same `ground.frag` and `ground_stamp.frag` (the client's
textures run v down the world, so it defines `GROUND_V_DOWN`). The module marks
the terrain's decals in `fx_queue_render` by the same materials as
`MaterialGroundRenderer._commands` (`host_ground`): blood, corpse bodies,
casings, black scorches and freeze shards, or no material. Each mark carries the
run's clock, which ages wet blood. While RTX is on, the host keeps the same three
companions of the terrain target and draws each marked decal into them as it
lands: the substrate (everything but blood), the ordered coverage, and the float
surface's three stamp passes. It draws the terrain into the world with the ground
program (`HOST_PASS_GROUND`). The lights carry what the ground adds: the
reflection tail, broad illumination, and a beam's three energy sections, computed
by the module as `continuous_beam.py` does (their widened supports also size the
body grid). The companions start from the terrain as it stands the first time
RTX needs them. A clear, a replay's terrain copy, or leaving RTX drops them.
Blood baked before then (in classic, or before the terrain copy a seek starts
from) stays in the substrate as painted terrain, without its wet film. A seek
bakes the logged decals after that copy again at their logged clock. WebGPU
keeps the surface in 32-bit floats where the device filters and blends them,
otherwise in half floats.
Monster Vision is heat, as in the Python port (see Perk illumination;
`crimson-core/game/rtx_heat.cpp`). While RTX draws, `creature_render_all` skips
the native aura quad and marks the trails instead (`host_heat_trails`, drawn
with `heat_trail.frag` under `GROUND_V_DOWN`); after each species' bodies,
`rtx_heat` draws the same frames again as `HOST_PASS_HEAT`, red carrying warmth
and alpha the overlay's opacity, which the host shades with `heat_body.frag` over
the atlas's part sizes blurred within each cell. Before the world begins, the
module sends every warm monster's footprint (`host_heat`); the host fades its
world-space trail buffer by the run's clock and stamps them (`heat_stamp.frag`).
The golden scene `hidden-evil` (`tools/rtx/scenes.toml`) is a real Hidden Evil run.

Fluid smoke takes the same solver and display shaders (`smoke_solver.frag`,
`smoke_splat.frag`, `smoke_impulse.frag`, `smoke.frag`). The module captures what
`sim/smoke_events.py` captures as each tick runs (`crimson-core/game/rtx_smoke.cpp`,
hooks in `game/rtx/rtx.patch`):
- sprite smoke spawns, read back after their caller colors them
- explosion puffs, with their delay and expansion
- muzzle puffs, which follow the firing direction, each with a jet of air
- rocket exhaust, which moves back along the flight, and detonation sprites
- the nuke's 15-second billows
- projectile and rocket wakes, and blast fronts from explosion bursts and rocket
  detonations

These hooks only read the run: no RNG, no state, and the verifier builds without
them. The module also runs `GpuSmokeSimulation`'s CPU side: delayed deposits,
retention and fade, impulse budgets and fixed 60 Hz steps. It hands the host the
solver passes as a command stream (`host_smoke`). The host runs them on its five
RGBA16F field targets. After the world's sprites (`bonus_render`, which ends with
the effects), the host integrates the display under the smoke's 16 lights and the
Sharpshooter sights (`host_smoke_draw`) into a composite at most 640 pixels
across, and puts it over the world premultiplied. While fluid smoke runs, native
smoke sprites and explosion puffs are not drawn.
The console's `rtxsmoke on|off` switches it, on by default. The Smoke display
setting gates it too. A mode change, a new run, or a restored run (a replay's
seek, a co-op rollback) clears the field.

Ion and Fire Bullets streaks draw as the same analytic beams as the Python port's
(`shaders/beam.frag`): the module computes each body and head quad as
`render/rtx/beam.py` does and hands it to the host (`host_beam`) in place of the
original's stamps, in the head colors the classic path picks (original bug 41
included).
On macOS the window is half-float from the start and opts into EDR while RTX is
on, following the headroom SDL reports each frame. Other platforms tonemap to SDR.
The mode never reaches a run's state, and the verifier (`core.wasm`) builds
without it.

Controls:

- launch flag: `crimson --rtx`, or `CRIMSON_RTX=1` (unattended captures)
- console commands, as in the Python port: `rendermode <classic|rtx>`, `togglertx`, `rtxsmoke <on|off>`
- `rendermode rtx` in the game folder's `autoexec.txt`, which the original runs at
  startup, keeps the mode across launches

## Browser client

In the browser, RTX needs the WebGPU renderer (`crimson-core/client/renderer_webgpu.cpp`): WebGL2 has no
extended-range output, so the WebGL2 renderer stays classic. The WebGPU renderer runs the same world target, tonemap
and beams through the same GLSL, translated to WGSL (`crimson-core/client/shaders.py`). On an HDR display
(`dynamic-range: high`) the canvas turns `rgba16float` with extended tone mapping while RTX is on. Browsers report
no headroom, so the tonemap rolls highlights off toward twice SDR white, which most HDR displays show without
clipping. Elsewhere it tonemaps to SDR.

The page's RTX switch sits beside fullscreen and shows only with WebGPU. `?rtx=1` or `?rtx=0` picks the mode for a
link, otherwise the switch's last state is kept in the browser. The console's `rendermode` and `togglertx` work as
on the desktop, and the switch follows them.

## Future direction

`crimson.render.rtx` is intended as the home for non-classic render
enhancements (beam acceleration, HDR additive tonemapping, and EDR output now,
advanced lighting next), while keeping `classic` as the parity reference path.

## Player lighting

Python RTX players receive the shared bounded weapon emitters through a separate
opaque cloth shader. The treatment combines stronger diffuse dome lighting,
painted texture relief, and a directional inner rim. It preserves the original
single-player and co-op tints and keeps a full ambient floor. There is no player
specular, transmission, material mask, or additional player shadow/occlusion pass.
The dome coefficient is 2.2, rim coefficient 0.8, relief strength 0.65, and the
combined added linear radiance is limited without changing hue at a scale of 1.4.
A small albedo lift and broad facing floor make the response readable on the
already-painted atlas. These are art-directed sprite normals, not 3D anatomy.

`player_lighting.py` owns a lazy shader and `player_shaders.py` defines its response.
The world pass selects the light list once for player and creature lighting, then
uploads it before drawing players. Living legs and torso share one shader scope;
the visible death sprite uses the same treatment. Black sprite shadows, radioactive
auras, shields, and muzzle flashes retain their original draw paths. With no lights,
the player uses the original shader without allocating the lighting shader. Classic
mode always uses the original path, including after switching back from RTX.

Per-layer orientation comes from UV/world derivatives evaluated before alpha discard,
with an identity basis for singular UV mappings. Relief and rim taps clamp to the
current animation cell. The base sprite keeps the original alpha-aware filtering and
4/255 cutoff. Point, finite beam, and annular illumination reuse the shared source
geometry and illumination gain; reflection-only tracers do not light player cloth.
Beam illumination comes from the shared beam profile's energy centroid (see weapon
illumination below), with squared radial attenuation.

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
Lights are uploaded once before the species passes. Specular beam intensity follows
the shared beam profile along the segment, and illumination comes from that profile's
centroid, independently of squared radial attenuation. Point lights and the native alpha cutoff remain intact.

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
attenuation and visibility. It preserves sprite alpha and the existing HDR limit.
This is a silhouette part-size appearance model, not anatomical thickness or traced
subsurface scattering. Square openings are orientation-dependent and can still
classify curved tips and corners as thin. The model does not distinguish skin from
claws/armor. Rounded body visibility now accounts for intervening creatures,
but the transmission calculation itself remains an artistic approximation.

Thickness textures are generated from the loaded source atlas on its first lit RTX
body pass, cached by that atlas's texture ID, and released when the world's lighting
resources close. Empty species and unlit/classic draws do not generate them.
Each 512×512 atlas adds a 256 KiB single-channel texture without mipmaps; generation
has a one-time readback and CPU preprocessing cost. Atlas binding happens once per
species body batch, with no per-creature texture uploads or additional render pass.

Only creature body passes use this shader. Contact shadows, hit flashes, freeze
and poison overlays, players, and baked corpses keep their existing paths.
RTX creature bodies retain a 0.60 linear ambient fill, with dynamic visibility
applied per emitter. Classic bypasses lighting entirely. GPU
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

## Weapon source profiles

`material_lights.py` describes finite luminous sources shared by the ground,
creature, and bonus passes. The visible projectile still uses its original draw
path. `MaterialLight.rgb` is linear source radiance; `illumination_gain` controls
diffuse spill, artistic edge lighting, and creature transmission, while `reflection_gain` controls
specular catches. A source can therefore be reflected without lighting nearby dirt.
`source_width` describes the reflection footprint in world units, independently of
the illumination `radius`. `reflection_radius` optionally specifies separate
finite reflection support. These are art controls, not calibrated radiometry.

`ProjectileEmission` profiles evaluate flight and impact state without modifying
the simulation:

| Family | Source and response |
| --- | --- |
| Ordinary tracers | Sub-unit-width reflected segments; no diffuse spill |
| Gauss | Narrow blue reflection, 12% of the former radiance, further restrained illumination |
| Ion / Fire Bullets | Strong tapered segments, preserving the reference rifle/fire treatment |
| Plasma | Warm atlas colors, distinct core widths and speed-scaled short tails; compact warm impact glow |
| Spider Plasma / Shrinkifier | Flight tint changes to the untinted warm impact artwork |
| Pulse | Restrained green source, followed by the warm impact sprite |
| Rockets | Localized exhaust sources, scaled by rocket type and respecting the glow setting |
| Detonations | Expanding reflection footprint and fading warm radiance |
| Flamers | Particles grouped into 64-unit spatial cells, with bounded accumulated radiance |

Ballistic/Gauss optical gain follows normalized life raised to 2.2, so the reflected
image fades more like the legacy alpha-blended tracer. This changes neither its
original lifetime nor gameplay. Other profiles retain linear lifetime gain;
emitter RGB is never gamma-decoded again in a material shader. Muzzle lights follow
the visible flash's suppression flags and warm artwork, with restrained spill for
ordinary weapons. Blade, Plague, and bubbles do not gain luminous sources.

Illumination and reflection independently select at most 16 sources by radiance,
response gain, and distance from the view center: to a segment's energy centroid
for illumination (so a streak's dark tail at the muzzle does not pull it toward the
view) and to the nearest point of the segment for reflection. Their union uploads
at most 32 entries; an entry selected for only one response has the other gain
zeroed. Shared sources are not counted twice, and reflection-only tracers do not
consume illumination slots.

A shotgun's pellets or a burst leave the muzzle together, so shots of one kind whose
heads and tails both lie within 28 units are one source: their radiance adds, the
merged segment runs between their brightness-weighted heads and tails, and it keeps
one shot's width. The width is never widened by the volley's spread, because every
body's shadow margin follows the widest source. A volley that fans out splits into
separate sources without changing its total light.

Every source has an ident that names it from frame to frame (its kind and slot; an
explosion's spawn position, since the effect list reorders). Each response fades a
source across its budget's edge over 6 ticks of the run's clock instead of popping
it: one leaving the budget dims out while the one taking its place brightens. A
source never seen before starts at its target, so a new shot lights at once, and a
rewind or a gap over a second starts the fades over. While sources fade the union
can outgrow 32 entries; it keeps the ones delivering the most light (both responses'
faded scores summed) and drops the faintest.

Ground roughness broadens the explicit source footprint. Creature diffuse dome
shading, the artistic silhouette rim, and thin-part transmission follow illumination
gain and reach, while specular
catches follow reflection gain and width. Bonus coat reflections and foil sheen
likewise remain independent of diffuse and artificial edge/back-wall lighting.
Material-specific approximations remain: these shaders are not reflections of
arbitrary non-emissive objects.

GPU tests exercise reflection-only sources beyond illumination reach, independent
gain controls, source footprint changes, alpha preservation, and the upload bound.
Transmission comparisons against a zero-transmission shader verify that
reflection-only sources retain specular catches without lighting thin limbs.
CPU tests cover independent selection budgets, union masking, finite-segment
ranking, volley merging, the budget fades, family colors/geometry, optical fade,
muzzle flags, expanding detonations, and flame grouping. Flame cell transitions and
EDR remain art-tuning cases; the daylight baseline and classic renderer are
unchanged.


## Ground reflection occlusion

Dynamic ground reflections now test the path from the receiving surface to the
same finite source point and height used by the reflection calculation. Each
source's specular contribution gets its own visibility. Ambient daylight and sky
reflection remain independent of that visibility. Projectile artwork and the
classic renderer are unchanged. Reflection-only tracers are occluded even when
their illumination gain is zero.

The five standard creature species use one rotated, size-scaled ellipsoid each, fitted
to the combined planar bounds of their former two body parts and retaining the
maximum part height. The single convex mass avoids forked body silhouettes while
preserving elongated shapes. Legs, arms, tails and players are absent; dying
bodies retain the collapse and fade described below. Their opacity follows the
creature tint. The volumes extend
slightly below the ground plane so their bases meet the surface, rather than
balancing a full ellipsoid on a single point. These are stable body approximations,
not frame-by-frame silhouettes or anatomical geometry.

A CPU-built spatial grid retains every body near the selected
reflection or illumination sources. Cells are 64 world units in small scenes and 32 with at least
512 body volumes (512 standard creatures); the finer grid reduces candidate
fetches in crowds. The resolution changes indexing only, not visibility.
Source-support cells are marked once, avoiding a body-by-source
culling loop. A growing,
renderer-owned RGBA32F texture holds cell lists and body transforms; no nearest-N
blocker cap causes shadows to switch between creatures in a crowd. The shader
traverses only cells crossed by the receiver-to-source segment, rejects nearby
cell members with a conservative planar bound, and exits when
visibility is effectively zero. Negligible reflections skip traversal entirely.
The grid includes the selected source endpoints outside the arena, and expanded
cell bounds account for the finite-source filter.

Visibility uses closest approach to each ellipsoid in its local coordinates,
with a smooth transition whose width grows toward the finite source. Wider
sources therefore produce softer edges. This is an analytic penumbra
approximation, not multi-sample area-light integration; overlapping partially opaque
volumes combine by strongest occlusion, avoiding seams between creatures. The
visibility test does not add ambient darkness, lengthen shadows artificially,
or lower the emitter for the occlusion test. Large source widths and heavily
animated silhouettes remain approximations. Direct lighting shares these volumes
and the grid while evaluating its own receiver/source segment.

### Crowd cells

Monsters don't collide, so a swarm piles hundreds of bodies into one cell, and a ray
used to test each of them in every cell it crossed: a late Plasma Shotgun crowd took
over a second of GPU time per frame in the native client. A cell where more than 16
bodies stand (`CROWD_BODIES`; a body stands in every cell its planar extent overlaps)
holds a crowd instead of its list: the opacity-weighted footprint of what stands there,
as a share of the cell's area (each body's footprint shared among its cells by
overlap), and its footprint-weighted top height. A ray crosses a crowd cell as an
absorbing medium, `exp(-3 × cover × length crossed in cells)`, over the part of its
path below that height; a body's own cell does not shade it. A body centered in a
crowd is listed in the cells around it only where it stands, without its soft or beam
padding, so a crowd's neighbors keep short exact lists, and a cell after a crowd
tests its whole list (the crowd tested none of the padded entries it shares). The
cost no longer grows with the crowd (that frame dropped to about 0.2 s, most of it
the original's own sprite fill), and packed bodies' shadows merge into one dark mass
anyway. Sparse cells keep exact
per-body shadows.


## Weapon illumination and soft body shadows

RTX keeps readable daylight fill (ground `0.50 + 0.12 * daylight_ndl`, living
sprites `0.60`, in linear RGB) while Ion, Fire Bullets and plasma add stronger
localized illumination. This is an art-directed lighting balance, not exposure
adaptation or a night mode. Blood absorption, aging, roughness and substrate/fluid
normals are unchanged. Overlapping emitters add independently. Fire Bullet source
gain is 4; the ground-only multiplier below applies on top of this shared source
gain without increasing creature, bonus or reflection brightness.

`lighting_shaders.py` shares source placement and visibility between ground and
creatures. Every receiver weights a finite segment by one profile
(`source_geometry.glsl`): radiance ramps linearly from the light's tail value at
its tail to 1 at its head. Ion and Fire Bullet streaks use a tail of 0, as their
stamps fade in from nothing; other segments keep 0.18, and ion arcs are uniform (1).
Ground reflections, creature and bonus highlights, and smoke scattering weight a
segment by this ramp along its axis. Illumination of the ground, bodies and players
comes from its energy centroid, `(1 - tail) / (6 (1 + tail))` lengths ahead of the
segment's center (a sixth of a streak). The source width supplies analytic soft edges. Fixed source positions avoid
receiver-dependent shadow sliding, but this is not integration over the whole
beam: it cannot reproduce every penumbra from the sixteen-sample lookdev study.
One, two and four samples were measured before choosing this approximation.
Ion and Fire Bullets use a coherent 24-unit source height for illumination and
reflections, so their reflections move closer to the visible streak than before.
Ordinary tracers remain reflection-only, and Gauss stays restrained.

The ground pass builds and uploads the spatial index once; the following creature
pass reuses it. Ground rays start at the surface; the artistic sprite lighting
receiver is 8 units high. Each sprite recovers its center from the unnormalized
UV/world derivative basis and excludes proxies carrying that owner center.
A 0.02-world-unit tolerance prevents precision speckles at fractional zoom without
requiring per-quad uniforms or breaking batches. Exactly coincident creatures
share exclusion; this is a documented limitation of the batch-preserving owner
representation. Tests retain blocking from a distinct owner only 0.1 units away.

The existing shadows setting disables the new direct-light and creature visibility
along with native contact shadows. Ground reflection visibility stays active,
preserving its independent policy. A blocked emitter does not subtract ambient or
other emitters' light. Bonuses still receive their existing analytical lighting
without these cast shadows; players and overlays remain on their original paths.
No flashlight, diffuse corpse occluders, individual legs, smoke or new normal maps
are introduced.


The energetic-source policy is explicit (`broad_illumination`), packed in the
otherwise unused ground source-direction Z lane. Only Ion, Fire Bullets, normal
plasma, energetic muzzle flashes, flame groups, rocket exhaust and detonations
use the broader grazing response. Other sources retain `0.22 * NdotL` and their
original relief bounds; changing this ground response does not rescale creature
or bonus gains.

Warm native OpenGL completion measurements on Apple M1 Pro (`OpenGL 4.1 Metal -
90.5`), at fixed replay
states (world drawing, including CPU submission, body-grid construction and
`glFinish` completion; simulation, HUD and UI excluded):

| Scene / target | Before | Initial candidate | Initial candidate, shadows off |
| --- | ---: | ---: | ---: |
| Ion Rifle, 67 living creatures, 1600×1000 | 5.61 ms | 7.80 ms | 4.86 ms |
| Synthetic 384 creatures / 16 bright sources, 1600×1000 | 12.87 ms | 32.75 ms | 13.88 ms |

Thirty measured frames followed eight warm frames per case. The shadows-off
setting also disables the existing sprite contact-shadow pass. These are frame
submission/completion timings, not isolated GPU timestamps or a whole-game FPS
guarantee. The dense case is deliberately severe and its roughly 20 ms added cost
is substantial. At 960×600, one/two/four illumination samples cost 18.25/26.24/42.13 ms
in that synthetic case; the shipped single centroid avoids the extra integration
cost. The corresponding earlier before measurement was 12.32 ms.


Review follow-ups normalize or collapse degenerate source axes consistently,
disable nonpositive reflection reaches before evaluating `smoothstep`, and avoid
empty grid traversal/uniform-array uploads. Shadows-off grid construction considers
only reflection support. Point-source creature reflections and diffuse lighting
reuse the same visibility result. Diffuse contributions below `1e-5` linear RGB
retain their radiance but skip shadow traversal, matching the existing reflection
policy. R32F native tests compare against tracing every positive contribution and
bound the additional light by `1.01e-5` per source (including float tolerance).

A matched follow-up run with the same hardware, resolution and warmup measured:

| 1600×1000 scene | Before review fixes (`67af1231e`) | After review fixes | After, shadows off |
| --- | ---: | ---: | ---: |
| Ion Rifle replay | 5.92 ms | 7.05 ms | 5.69 ms |
| 384 creatures / 16 finite beam sources | 30.95 ms | 29.94 ms | 12.53 ms |
| 384 creatures / 16 point sources | 31.45 ms | 27.31 ms | 13.13 ms |

The point-source stress case improved by 13%, while this separate-process Ion
run regressed by 19% (p10/p90: 4.41/6.75 ms before, 5.80/9.88 ms after). A bounded
follow-up interleaved the old, reviewed, and reviewed-without-diffuse-gates shaders
in ABC/CBA order twice, with the same current CPU renderer. Each of the four
blocks per variant used 10 warm and 20 measured frames. Pooled Ion medians were
6.01/5.80/6.19 ms respectively; p90 values were 9.52/9.56/9.65 ms. The slowdown did
not persist under interleaving, but this does not establish a general typical-scene
speedup. These small optimizations do not remove the substantial dense-scene cost.
Before/after SDR captures differed by at most one 8-bit code value in at most 175
of 4.8 million RGB channels; all body profiles and artistic lighting settings
stayed fixed.

### Sharpshooter sight reflection

The native red sight contributes a narrow reflection source for each living
Sharpshooter player. It uses the same stored endpoints as the visible quad,
including the offset near the gun. Its axis points back toward the gun so the
reflection fades to black at the distant end, matching the visible sight rather
than a projectile's bright nose. Its art-directed red radiance is 1.3 with a
1.2-world-unit source width, making the glint readable over red blood without
changing the native sight artwork. It adds no diffuse illumination. Wet blood,
ice and other reflective materials use their existing roughness, freshness and
occlusion response. Bonus orbs receive the same source through their curved
resin-coat reflection; the aiming cursor remains a presentation overlay.

### Live ground diagnostics

In RTX mode, **F6** cycles ground and smoke diagnostic views; **Shift+F6** cycles backward.
This works during gameplay and in the standalone replay viewer, including while paused.
Return to `shaded` for the normal scene. The in-game console also accepts
`rtxdebug <name>`: `shaded`, `substrate-normal`, `fluid-normal`, `freshness`,
`blood-depth`, `reflections`, `direct`, `direct-unshadowed`, `visibility`,
`albedo`, `roughness`, `height`, `materials`, `ambient`, `no-direct`,
`smoke-density`, `smoke-heat`, `smoke-flow`, or `smoke-light`.

These are display-only selections: they survive replay seeks, do not affect the
simulation/recording, and have no effect in classic mode. Ground maps hide live
sprites, particles and aim overlays; the HUD and playback controls remain usable.
Raw normals/material channels bypass the world HDR shoulder and game gamma
multiplier. Normals encode XYZ as `normal * 0.5 + 0.5`. Radiance views use a fixed
`c/(1+c)` mapping followed by gamma encoding, independent of display EDR headroom.
Explicit `material_scope(debug=...)` probes retain linear radiance for GPU tests.

`direct` includes dynamic diffuse lighting after creature shadows;
`direct-unshadowed` evaluates the same material/light response before occlusion.
`visibility` is their linear luminance ratio across all selected lights: white is
unblocked, black is fully blocked, and blue indicates no direct illumination.
It is not a separate geometric mask or a measure of ambient light. `reflections`
shows dynamic reflections only; `no-direct` is a matched scene comparison: it removes only dynamic ground
diffuse lighting, preserving entities, aim overlays, reflections and the ordinary
HDR shoulder/game gamma. Unlike the isolated maps, this can be compared directly
with `shaded`.
`albedo` shows the substrate before blood absorption. `materials` shows blood in
red, corpse coverage in green, brass in blue, and ice in cyan.

The smoke views draw the fluid alone over black, through the same reduced-resolution
composite as the scene. `smoke-density` is the column's opacity at the field's fade:
black is clear, white is opaque. `smoke-light` is the weapon, exhaust and sight light
the smoke scatters, without its sky fill, mapped like the other radiance views.
`smoke-heat` and `smoke-flow` read the raw simulation state across the whole domain,
including air that has lost its smoke: heat ramps black, red, yellow, white up to the
temperature cap that raises and thickens the column; flow hue is the planar velocity's
direction and brightness is `1 - exp(-speed / 60)` for speed in world units per second. With no
active field there is nothing to show; the solver does not run without a medium.


## Explosion emission and pressure fronts

Nuke and Final Revenge use generic explosion effects rather than secondary
`DETONATION` projectiles. Each `spawn_explosion_burst` now records one render-only
explosion event, independent of the one/three/four atlas pieces selected by the
detail preset. It uses no additional RNG and does not change the native effect
entries, simulation damage, or Classic drawing. Rocket-impact bursts opt out of
the additional central light because their secondary detonation already owns it.

The source illuminates terrain and creatures and reflects from wet materials.
RTX archives the actual fireball sprites chosen by the native spawner, without
extra RNG or additional pieces. It samples their position, scale, rotation and
alpha at half age, extending their visible 0.7-second lifetime to 1.4 seconds.
Native effect slots still expire normally; flash timing stays unchanged. RTX smoke
persists in the presentation fields described below. Classic draws the original
slots at normal speed.
Rocket bursts retain their native fireball timing as well as their existing light.

The emitter rises from 12 to 80 world units (times blast scale) with a smoothstep
over 0.8 seconds. This height is art-directed: the sprites have no native Z data.
Source width follows 35% of the growing, drifting fireball sprite bounds, clamped
to 12–90 units times blast scale. A low early source gives long shadows; rising
height shortens them and the growing source softens them. Radius stays at 330
times blast scale. The linear-radiance envelope is `0.2 * exp(-t / 0.08) +
0.8 * min(1, max(0, 1 - t / 1.4) / 0.75)^1.1`: a brief flash, a sustained bright
phase through 0.35 seconds, then a fade with visible fireball alpha. RGB is
`(1.8, 0.92, 0.3)` times this envelope; illumination/reflection gains are 6/1.2.
These values describe visual tuning, not calibrated nuclear radiometry. Missing
fireball sprites do not create a lingering invisible lamp.

In RTX, the explosion-owned atlas ring becomes a warm, translucent shell plus a
thin pressure distortion. Freeze, shield and other rings keep their native drawing.
The shared render-only profile starts after 0.05 seconds and lasts 0.65 seconds:
`radius = (30 + 650 * elapsed) * blast_scale`, with full strength through elapsed
0.28 seconds, then a smoothstep fade. Shell alpha is `0.36 * strength *
min(1, (100 / unscaled_radius)^0.65)` using the original RING texture tinted
`(190, 163, 122)`. A narrow compression/rarefaction band displaces the world by up
to 4.5 pixels times strength, with a transparent interior. A separate RGBA16F
target avoids texture feedback, before display tone mapping and before HUD/UI.

A distinct annular source follows this shell: height 16, source width 8,
illumination support 85 and reflection support 100 (all times blast scale),
illumination/reflection gains 1.8/0.65, and RGB `(0.60, 0.39, 0.18)` multiplied by
`strength * sqrt(min(1, 100 / unscaled_radius))`. It lights terrain, creatures and
bonus shells/icons, and reflects from wet materials. The pressure wave itself is
not physically emissive: this warm source is an artistic representation of the
visible blast shell. Rocket bursts use it too, without duplicating their central
secondary-detonation source.

`MaterialLight.ring_radius` explicitly describes the annulus; segment length is
independent. Shaders choose the nearest ring point for illumination and the nearest
ring point to the reflected eye ray for ground/bonus reflections. This is a
continuous-shape approximation, not integration over the full circumference.
Source ranking measures distance to the circumference; occlusion bounds cover the
entire ring plus its support, including blockers inside the circle.

The extra target and shader allocate lazily; frames with no active front use the
original tonemap path. One fullscreen pass handles up to 16 simultaneous fronts.
Explosion metadata is bounded to 128 events, expires after 1.4 seconds (0.7 for
rocket bursts) and clears
with the effect pool. Freeing a native slot also releases its visual owner, including overflow slots,
so slot reuse cannot hide a later sprite. The shell remembers successful native
allocation, then follows its own bounded event age; a reused slot cannot change
its geometry or restart it. Archived fireball parameters stay separate from the
reusable native slot.


### Dying creature casters

A killing hit does not remove the visible body immediately. Dynamic illumination
and reflection proxies follow the native death slide: current position, rotation
and size remain authoritative, while height falls by `smoothstep(0, 16,
death_timer)`. Opacity fades over the final quarter of that collapse, before the
corpse is baked at timer zero. A newly killed body therefore keeps its shadow;
the shadow shortens and fades as it settles, rather than blinking off at HP zero.
The later fading corpse sprite has no elevated proxy above its baked ground
material. This uses existing simulation state only and does not alter death
movement, damage, corpse timing, RNG or Classic rendering.


## Extended beam illumination

Python RTX uses a three-section approximation for Ion Rifle, Ion Minigun, Ion
Cannon and Fire Bullets ground lighting by default. Ion direct illumination uses
a 4x gain and a maximum 25% local ambient reduction; Fire uses a 3x ground
gain and a maximum 15% local ambient reduction. These are presentation settings:
simulation and classic rendering are
unaffected. No separate beam console command or replay flag is required:

```sh
uv run crimson replay play 18-survival.crd --rtx
```

### Three energy-weighted sections

The source follows the authored beam's stamp spacing, scale, brighter head and
current length. A small radial lookup projects the narrow emitting core onto
its longitudinal axis. Three cells sample this profile and retain their energy
and centroid. Their weights sum to the existing light budget; the visible beam
art is unchanged. Ion Rifle and Minigun source sizes share the same scale table
as the projectile renderer.

Each section casts through the existing rounded creature proxies and spatial
grid. For each body, a ray/ellipsoid discriminant becomes a quadratic in the
longitudinal source position. Clipping its blocked roots to the section interval
integrates the emitting segment analytically. A body blocks only between the
receiver and the light, so one taller than the emitter does not shadow from
beyond it. Two Gauss-Legendre taps at plus/minus `1/sqrt(3)` of the transverse
half-width average the remaining emitter dimension. Umbra and penumbra therefore
change with the body's direction around the projectile instead of using three
point or disc lights.

Section half-lengths retain their full profile extent rather than the old
four-unit cap, and the same analytic approximation is used at every body
height. Overlapping proxies retain the existing minimum-visibility semantics,
and dying bodies retain their shared collapse/fade behavior.

Preparation uploads one small uniform array and reuses the occlusion texture.
Each cell near a beam source also holds a beam list, its bodies padded by the
largest section half-span in world units; point lights, reflections and creature
shadows keep their narrow lists. A section walks the beam lists along its center
ray, rejects bodies outside its ray fan (the triangle from the receiver to both
section ends), and tests each body only in the first walked cell that lists it.
Conservative grid-only source copies add the endpoint halo. They never replace
the original light uniforms used by reflections or creature lighting. A bounded 128-entry profile cache handles
repeated shapes; a cache miss samples only nearby stamps. There is no per-beam
candidate texture or interval sort.

Beams only add light. They used to dim the ambient within 300 units of the beam (up to 25% for ion, 15% for Fire
Bullets), regardless of visibility. Past the beam's lighting radius that left a ring darker than plain ground. The
golden scenes measured that dip's effect at under 4 levels for 99% of pixels, so it was removed: shadows alone now
give the contrast. Use F6 `direct`, `direct-unshadowed`, `visibility`, and `ambient` maps to inspect the beam's light.

### Cost and visual limits

Three sections were selected over one and five using native moving-beam renders.
One remains visibly closer to a point source; five costs more without a useful
improvement in the inspected scene. The ground shader includes this path; frames
without eligible beam sources skip preparation and ignore stale section uniforms.

Three visibility queries per beam are still more expensive than the previous
centroid, with two analytic chord evaluations per candidate body and section.
Dense scenes with many simultaneous beams remain costly. Two transverse taps do
not reproduce a dense sampled reference exactly, but avoid the old separate
shadow lobes at substantially lower cost. A section's fan is as wide as the
section, so its walk fetches more list entries than a point light's; that
traversal, rather than the chord evaluation, dominates its cost.

### Ion impact arcs

Ion shots also register the visible post-impact connections as RTX sources, and
glow where they meet creatures. Drawing and lighting share the same target query: only the
impact/fade phase, the original slot-zero exclusion and collidable lifecycle,
weapon scale, and Ion Gun Master reach apply. Fire Bullets do not chain.

Each connection contributes a finite segment source, fading with the visible arc.
Its contact is always a disc, so it is not a light: an additive ground glow
(`contact_glow.py`, `contact_glow.frag`) in the arc's color, a 60-unit disc drawn
before the creatures, leaves the light budget to the arcs and everything else when
an ion crowd would otherwise fill it. Arc segments are uniform (a tail of 1), so
their reflections are even along the arc and their illumination centroid is its middle. The new
sources use restrained independent gains, without the main Ion beam's 4x ground
gain. At most four connections
per impact contribute sources, ranked by segment distance to the view center
(with endpoint distance as a tie-breaker). All arcs remain visible in the artwork.
This bounds source preparation as well as brightness in dense crowds. This
is an artistic brightness cap, not a physical energy simulation. Ordinary global
source ranking and its 16 illumination / 16 reflection limits still apply.

The original beam stays lit during its fade. Arc sources add illumination and
reflections through the shared ground, creature, and bonus light list. Classic
artwork, damage, target selection, and replay state are unchanged.

## Persistent fluid smoke

GPU fluid smoke is **on by default in RTX**. In the game, `rtxsmoke off`
immediately clears the fluid and restores native smoke sprites; `rtxsmoke on`
re-enables it. Standalone playback accepts
`crimson replay play <replay.crd> --rtx --no-rtx-smoke` to disable it.
`--rtx-smoke` explicitly enables both fluid smoke and RTX. The console choice belongs to the current game/replay
world and is not saved to config.
The existing Smoke display setting still controls whether the fluid runs.
Classic always uses its native smoke path.

When enabled, RTX replaces native smoke puffs with a persistent simulated density
field. Rocket exhaust, rocket impacts, and other native smoke emissions feed the
same system. Nuke pickup explosion puffs request 15 seconds of retention; ordinary
smoke requests 10 seconds. Density decays throughout that time, with an additional
soft fade over the final two seconds. These are maximum retention windows, not a
promise that every small puff remains visible for that long.

Implementation: `render/rtx/gpu_smoke.py`, `gpu_smoke_shaders.py`, `smoke.py`,
`smoke_shaders.py`, and `sim/smoke_events.py`. Simulation state stays in RGBA16F
render targets: density, temperature, and planar velocity. OpenGL 3.3 fragment
passes perform advection, pressure projection, and source deposition. This needs
neither compute shaders nor a per-frame CPU grid upload/readback. Python retains
immutable emission batches and presentation clocks. `smoke_simulation.py` remains
an explicit CPU reference for offline comparisons; it is not a runtime fallback.
Failure to initialize the GPU solver or display restores native smoke.

### Native events and lifecycle

Each deterministic tick captures immutable copies of actual `SpriteEffectPool`
smoke spawns and `EffectPool` explosion puffs, including command-triggered spawns.
No additional gameplay random numbers are consumed. Negative native effect ages
delay injection, and native expansion contributes planar velocity. Nuke retention
is explicitly marked around the nuke burst, so ordinary rocket explosion puffs do
not inherit the longer lifetime. Large general-effect puffs weight their source
strength by native tint luminance: their dark tint must not become an opaque gray
disc that obscures the finer sprite smoke. This is an artistic conversion into a
shared scattering medium, not a physical mass calibration. The explicit nuke
presentation profile increases that dark-puff strength eightfold, distributes it
into irregular overlapping billows with local curling motion, and lowers density decay
from 0.20/s to 0.12/s so the extended aftermath remains visible. The shared domain
gradually returns to the ordinary decay rate after receiving a nuke deposit;
this does not add mass to smoke already there. Capture bookkeeping lives outside native state
and checkpoint serialization.

Presentation consumes every tick's batch, including empty batches, using its
simulation delta. Fixed 60 Hz substeps accumulate fractional slow-motion time;
pause and extra draws do not advance the fields. Forward replay playback uses the
same presentation handoff. Level/reset/session replacement, RTX mode changes, and
disabling the smoke setting clear fields and delayed deposits. Re-enabling RTX
starts with new emissions. Native smoke sprites and general explosion puffs are
not drawn while fluid smoke is enabled, including when the solver is empty or at its allocation cap.
Classic retains the original sprites.
Checkpoint restoration and explicit replay seeking clear this transient history
instead of storing it in the deterministic checkpoint. Undrawn seek ticks do not
leave a GPU catch-up queue; normal playback and diagnostic views retain every tick.

One shared 320 × 320 domain covers the arena plus a 128-world-unit guard band
on each side. All trails exchange flow and share light extinction; there are no
internal patch walls or separate alpha layers. Sources rasterize only their
bounded footprint. Sampling outside the domain returns zero; open pressure
boundaries and an absorbing outer band allow outflow instead of reflecting it.
The domain is fixed, so a moving camera cannot relocate existing smoke and no
GPU occupancy readback is needed to resize it.

Empty scenes perform no fluid steps. Domains retire at the end of their retention
window. New deposits extend remaining retention, baking any existing final fade
into density and temperature so old smoke is not restored. Nuke decay relaxes
back toward the ordinary rate with a roughly 14-second time constant. Delayed
emissions remain capped at 1024. Sources outside the padded arena do not allocate
new simulation domains.

### Motion and light

The GPU solver uses semi-Lagrangian advection for planar velocity, 12
pressure-relaxation iterations, vorticity confinement, and damping. Density and
temperature use conservative upwind face fluxes. A donor outflow limiter keeps
these fields nonnegative even when an impulse moves air farther than one cell per
step; at such speeds it trades transport speed for stability. Shared face fluxes
preserve column mass apart from source deposits, decay, open-boundary outflow and
RGBA16F rounding. This prevents an expanding blast from multiplying smoke.
The CPU reference's MacCormack scalar correction and finer growing grid are not
pixel-equivalent to this bounded GPU approximation. Sources inject presentation motion and
expansion; a small fixed planar breeze supplies background drift. RTX muzzle
puffs use the firing direction instead of the native sideways velocity, with a
resolved elongated footprint and a short jet with paired vortices. Rocket exhaust
moves backward along the flight direction instead of inheriting the native
cosine-for-both-components drift. These overrides affect only copied smoke events;
native sprite values, RNG, collision, damage and replay checkpoints are unchanged.

Projectiles deposit velocity-only wakes along their actual swept paths. Ion, fire,
plasma and rockets have stronger wakes than ordinary bullets. Muzzle jets and
wakes enter before pressure projection; explosion fronts deliver a short expanding
radial impulse after projection so the incompressible solve does not erase their
expansion. Neither impulse creates smoke or heat. All rocket detonation paths and
nuke bursts contribute blast motion, including low-detail explosions without
smoke puffs. No visible medium means no additional fluid simulation is needed.
Per-tick GPU impulses are capped at 64, prioritizing blasts and muzzle jets before
wakes; at most 16 blast fronts persist. New forces reuse the existing solver and
pressure iterations.

Rocket exhaust and impact deposits use 40% of the old source strength, and ordinary
general-effect explosion puffs use 60%. The nuke profile retains its existing
strength and decay. RTX rocket explosions omit the visible pressure shell, shell
light and screen distortion; their central explosion lighting and their motion
through existing smoke remain. Classic explosion rings are unchanged. Temperature
controls an assumed vertical density profile in the display shader. This is a
shallow 2D flow approximation with a 2.5D display, not a simulated 3D volume or
vertical buoyancy model.

The display integrates 14 vertical samples and six transmittance samples per
light into a reusable RGBA16F viewport buffer capped at 640 pixels on its longest
axis. Premultiplied reconstruction preserves HDR radiance and translucent edges;
the world itself stays at full output resolution. It uses the shared native weapon sources, including rocket exhaust,
Fire/Ion beams, and explosion lights, with the existing 16 illumination-source
limit. Fractional source gains are preserved; gains above four are capped for
smoke response. A segment scatters by the shared beam profile, so a streak's
tail lights the cloud less than its head. Up to four living players' native Sharpshooter sight segments
scatter as narrow red beams only inside density, rather than broadly illuminating
the whole cloud. The ordinary sight artwork remains unchanged.

Smoke composites after native sprites, outside their alpha-test shader, inside
the HDR world and pressure-front composition. Ground diagnostic maps hide the composite while continuing to drain queued fluid updates; the smoke views show it alone.
The renderer approximates single scattering and self-shadowing within the shared domain;
the assumed slab does not resolve creature geometry. Broad sky extinction gives
billows some form after local emitters fade. Rocket exhaust uses a separate
sixfold scattering response, without increasing its ground or creature lighting.
Simulation cost scales with grid area and pass count; display cost scales with
shaded pixels and lights. Density columns are sampled once and reused at every
integration height, preserving height-dependent optical depth. GPU timings and
full-frame timings must be measured separately; reducing CPU simulation time
does not imply the rest of the RTX frame is free. Shader/solver resources prewarm
on the first enabled frame, moving the initialization cost out of the first shot.

A synchronized M1 Pro benchmark of native rocket/nuke inputs and a 99-creature
fixture measured 1.6–2.5 ms median simulation and 0.6–0.9 ms smoke display costs.
At 1024 × 768, completed world-frame medians were 6.8–11.0 ms, including native
simulation updates. At 2048 × 1536 they were 8.6–13.1 ms. The dense high-resolution
case reached 22.6 ms at p95 (18.9 ms with native smoke); this is not a universal
60 FPS guarantee. The benchmark excludes HUD, window presentation, audio and
video encoding. The console/CLI off switches remain available for slower GPUs.

## Perk illumination

RTX Radioactive retains the original additive green aura and its render-clock
sine pulse. A 100-unit green material source follows each player, including the
native aura's post-death presence. The source uses height 18, width 13, RGB
`(.10, .70, .07)`, and illumination/reflection gains `3.8/.8`, multiplied by the
original aura alpha divided by its mean `.4375`. It illuminates ground and bodies,
reflects in wet materials, and uses the shared creature-volume visibility path.
The display shadow setting controls direct shadows as for other material lights.
Reflection visibility remains part of the existing reflection model. Radioactive
uses the ordinary source budget; it does not alter damage range or pulse timing.

Monster Vision shows living monsters as heat (`render/rtx/heat_vision.py`). It
keeps the native death fade, entity transition alpha and sprite-shadow
suppression; classic keeps the original yellow aura texture.

- Bodies: after each species' body pass, the same sprites draw again with
  `heat_body.frag` in the ironbow ramp (`ironbow.glsl`), indexed by the creature
  silhouette density: two 5×5 alpha blurs within each atlas cell, made once on
  the atlas's first heat draw (one texture tap per fragment). Density preserves
  cool extremities; a fixed torso lobe and a soft head lobe preserve hot spots through
  articulation. Zombie walking frames carry head positions baked with OpenCV
  Lucas–Kanade optical flow (`tools/rtx/track_heat_heads.py`, `heat_heads.json`);
  lizards use 35% of the tracked motion. The other species and non-walking cells
  retain their fixed positions. Green/blue tint bytes carry the per-frame center
  in both renderers, with no tracking dependency or work during gameplay.
  Bounded detail from the sprite color already fetched with its
  alpha brings back the artwork's surface features, without extra texture taps.
  This retains a wide magenta-to-white temperature range without the
  square-opening thickness proxy's abrupt jumps between animation poses.
  All species use the same response; transmission lighting retains its separate
  thickness proxy.
  The overlay's opacity is Monster Vision's fade times
  `.88`, never the creature's tint alpha, so Hidden Evil's near-invisible aliens
  show in full. Red in the tint carries warmth: the native death fade, cooled to
  30% while Freeze holds the monsters, following Freeze's own fade out. Scene
  transitions fade the overlay's opacity, never its warmth.
- Trails: a world-space float buffer at half the terrain's resolution. Each
  drawn frame fades it by the game time since the last (half-life 0.3 s, so
  slow motion leaves the same trail per distance), then max-blends a soft
  footprint (45% of the creature's size) at every warm monster. A frame gap
  over a second, a rewind, or a terrain reset starts it over. Where the aura was
  drawn, `heat_trail.frag` adds the buffer under the view to the ground as faint
  ironbow heat, under every body. Stored heat ignores scene transitions; the
  composite fades with the scene's entity alpha, like the bodies.

The sensor is selective: fire, explosions and beams keep their own look and do
not wash the monsters out. Heat adds no material lights and changes no
simulation, RNG or replay state. The native and web clients draw the same heat.
