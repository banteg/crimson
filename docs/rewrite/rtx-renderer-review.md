---
tags:
  - rewrite
  - rendering
  - review
---

# RTX renderer review

Reviewed: 2026-10-23. Updated: 2026-10-26, after follow-up reviews, measurements on
the golden scenes and on late-game replays, and the work they led to.

Scope: Python RTX rendering and the client port that shares its shaders (the
native GL client and the WebGPU web client): artistic direction, effect
interactions, and implementation architecture.

This is a working plan, not a record: it lists what shipped, what turned out to be
wrong, and what is left, in the order we intend to take it. Finished items keep a
line and a link; the evidence lives in their pull requests.

## Assessment

The renderer is already more than "bloom plus dynamic lights": persistent ground
materials, analytic beam sources, creature occlusion, archived explosion visuals,
pressure fronts and simulated smoke form one system, with debug views, pixel
tests and golden scenes behind it.

Its remaining weakness is coherence. Ground, creatures, players, bonuses and smoke
share a light list, but each still limits highlights its own way, players and
bonuses do not take part in occlusion, and some passes behave like separate layers.
The direction stays:

1. **Preserve the original art: albedo, silhouettes and readability.**
2. **Make Classic-with-no-dynamic-light the reference, then add RTX energy.**
3. **One source model across every receiver.**
4. **Spend new work on cross-effect interactions, not more isolated glow.**
5. **Keep gameplay readability ahead of physical purity.**

## Shipped

| What | Where | Result |
| --- | --- | --- |
| Comparison tooling | #882 | `crimson replay render --rtx`; golden scenes in `tools/rtx/scenes.toml` captured classic and RTX by `tools/rtx/golden.py`; native client GPU time per pass (`CRIMSON_GPU_TIMERS`) and exact-tick captures (`CRIMSON_CAPTURE_TICK`) |
| Magenta blood | #882 | The cool sky reflection over wet pools was the only blue term; it stays cool over ice and goes neutral over blood, so pools read red again |
| Negative light around beams | #882 | The ion and Fire Bullets ambient dips are gone from Python and the client: beams only add light, shadows give the contrast |
| Beam light along a segment | #883 | Ground, reflections, creatures, players, bonuses and smoke weight a segment with one profile (`segmentRadiance` in `source_geometry.glsl`) |
| Beam shadows | #880 | Projected two-tap beam shadows; the densest ion scene's ground cost fell from about 12 ms to 2 ms |
| Monster Vision | #884, #885, #889 | Heat instead of a lamp: ironbow bodies keyed to Monster Vision's fade (Hidden Evil's near-invisible aliens show in full) and fading world-space trails, in Python and both clients; the aura's ground light is gone. Smooth silhouette density stopped pose-to-pose flashing |
| Stable light selection | #886 | Stable idents (kind and slot, an explosion's spawn point); each response fades a source across its 16-source budget edge over 6 ticks of the run's clock. Also: volley merging, crowd cells for piled swarms, and ion contacts as ground glows instead of lights |
| Analytic beams and effects | #887, #888 | Beams integrate a two-Gaussian fit of the glow in closed form (no beaded spine, no slow-motion lag); plasma, warm glows, auras, rings and ion arcs are analytic, with batched radial sprites |
| Frame budget tooling | #892, #899, #901 | Per-pass draw counts and pixels beside the GPU timers, Classic world timers, bake and heat-stamp marks. Scripted runs end by themselves, run in the background, ignore the desktop mouse and focus; the window title names the mode and replay |
| Tonemap white drift | #893 | The drift toward white eases in and out, so glows no longer show contour lines where they crossed its old slope breaks |
| Lights inside bodies | #894 | A body no longer shadows a light inside or against it (a muzzle in a monster, a beam section through one) |
| Frozen-crowd shadow cost | #895, #896 | Shadow lists were padded by the widest source's penumbra for every body; beam lists drop it, and the penumbra follows at most 8 units. A frozen crowd's ground fell from 118 to 39 ms |
| Smoke half-circle | #897 | Smoke behind a shot with a dark tail cut off along a hard line; it now weights the shot's segment over its whole reach |
| Ion arc pile | #900 | A Shock Chain into a piled crowd drew 5,351 arcs over the same pixels (93% of Classic's world fill). Each shot now draws at most two arcs per small cell, and RTX arcs batch: Classic's world 160 to 35 ms at the peak, RTX sprites 27.5 to 4.3 ms |
| Volleys are one trigger pull | #905 | Volley merging joined any nearby shots of a kind, so converging spider plasma and crossing Fire Bullets merged and split frame to frame. A volley is now one pull's pellets; a pellet that leaves hands its light over across 6 ticks and never rejoins |
| Players and bonus shells cast shadows | #906 | A torso ellipsoid per living player and the shell's dome per bonus join the creature body grid in Python and the client; their own muzzle flash and aura stay unshadowed |
| Python-vs-client frame diff | #907 | `tools/rtx/golden.py` compares the two renderers on the golden scenes |
| Pulse Gun | #908 | Shots draw as the original sprite's fitted dome with an HDR front glow, lit by a segment across the front |
| Ground pass in late-game crowds | #909 | Beams light as one extended source (a closed-form integral of the stamp density, with one binned shadow walk), and their visibility is drawn at a quarter of the ground's resolution in passes of four. The late plasma run's ground fell from about 97 to 20 ms at its heaviest; costs and visual limits are in [RTX rendering](rtx-rendering.md#cost-and-visual-limits) |
| Body grid upload | #910 | The client rotates the grid through three textures, so its upload never waits on the GPU |
| Eval tooling | #911, #912 | One scripted run measures several moments of a replay (`CRIMSON_WATCH_MOMENTS`), and `CRIMSON_WATCH_CACHE` keeps a prepared replay on disk: classic 8.9 to 1.7 s and RTX 23.7 to 11.6 s per launch on the late plasma run |

## Disproven or dropped

- **Painted blood detail in the stamp.** The five blood sprites are flat deep red
  with nearly no variation; their shape is all alpha, which the stamp already uses.
  Classic pools get their texture from dirt showing through overlapping translucent
  red, and RTX keeps that dirt.
- **Restoring blood into the substrate.** The clean substrate exists so absorption
  never applies twice to already red pixels. If a pigment target is ever needed, it
  is a separate ordered target, not blood put back.
- **A globally darker baseline to replace the beam dips.** Rejected: it trades
  Classic readability for contrast that shadows already provide.
- **A second, overflowing smoke light budget.** Smoke already receives at most 16
  illumination sources from the shared selection.
- **Multiple render targets for stamps.** raylib's render textures carry one color
  attachment, the client stamps per decal draw anyway, and stamping runs only on
  ticks that bake decals.
- **Approximate fast activation from the painted ground.** It cannot recover
  deposit age, material order or the clean substrate. Exact replay stays the
  default; the client's documented gap (blood laid before RTX reads painted) stands.
- **Exact equivalence between different approximations.** Compare approximations
  against a reference within stated tolerances instead.
- **"Smoke bands double the smoke march."** Splitting the existing height slices
  between a low and a high band adds one composite, not a second march.
- **A stencil cap on overlapping additive draws.** Counting the arc pile's fragments
  per pixel was pixel-exact, but on macOS GL a stencil-rejected fragment costs about
  as much as a drawn one (156 against 157 ms with every arc fragment rejected). Only
  geometry the CPU never submits helps; an exact per-tile CPU cut was modelled at 12%
  of the fill, and merging arcs was simpler for an invisible difference.
- **Bigger shadow-grid cells.** They only looked faster because more cells became
  crowds; with the crowd threshold scaled to cell area they were slower.
- **A half-resolution additive layer.** It halved the arc pile but cost 0.4 to 0.9 ms
  in ordinary scenes.
- **One-source beams at full resolution alone.** The single source made the light
  more accurate but its shadow walk was mixed (18% faster to 65% slower against three
  sections); the win came from drawing that visibility at a lower resolution.
- **Reading CPU frame time with GPU timers on.** Each `CRIMSON_GPU_TIMERS` mark
  submits work, which inflates the CPU's frame time. Profile the CPU with a sampler
  and the timers off.

## Remaining, in priority order

### 1. What is left of the late-game frame

With #909 the ground pass no longer dominates. Next, measured on the late plasma
run with the timers off:

- **CPU stalls.** The viewer's frame hold copies the back buffer every frame (about
  42% of the stalled CPU time), and smoke switches framebuffers per slice (about
  24%). Both are client-side and invisible in GPU timers.
- **RTX seeks.** Rebuilding the terrain from a kept copy bakes the logged decals
  again, and RTX bakes about 23 times slower than Classic (9.3 against 0.4 s for
  the run's 34,000 batches), so a seek far from a copy stalls for seconds.
- **Quarter-resolution beam shadows.** Shadow tips step by four pixels in direct
  light, and blockers thinner than a texel lose their contact shadow; the shaded
  frame hides most of it (p99.9 within two levels on the golden moments). If it
  shows in play, try an edge-aware upsample before raising the resolution.

Stable light selection (#886) may still need ranking by contribution to the visible
receivers if captures show pops.

### 2. Contact shadows under lit players

Players and bonus shells now cast body shadows (#906), but the native blob shadow
still draws under them. Keep only a restrained contact-shadow part of it where
dynamic lights take over, so lit areas do not show a pasted-on double shadow.

### 3. Lit freezing, then hot smoke

- **Frozen creatures as a material.** `draw_freeze_overlay` still stamps an unlit
  shard sprite over lit bodies. Feed freeze into the creature material instead:
  reduced transmission, thin edge Fresnel, restrained specular, the silhouette and
  lighting kept, and a brief glint and cold steam on shatter. Heat already cools
  frozen monsters, so the two read together. In the client the freeze overlay is
  one loop in `creature_render_all` and can be marked like the heat pass.
- **Hot smoke.** Every emission adds temperature, but temperature mostly shapes the
  column. Give fresh explosion smoke a short warm emission that cools quickly, keep
  old smoke neutral, and separate soot, heat and steam source profiles.

### 4. The unlit baseline (a decision, made from captures)

- **Ambient level.** The ground ambient was cut from 0.94 to 0.50 in #813 so weapon
  light reads against it; unlit RTX ground is now noticeably darker than Classic.
  Whether to raise it is an art call to settle on the golden scenes. Either way,
  `rtx-rendering.md` still says unlit terrain keeps its Classic brightness, which is
  out of date.
- **Blood saturation.** With the hue fixed, RTX blood is still grayer than Classic's
  deep red (red about three times green, against four to six in Classic), from the
  gray sheen and wet-soil darkening. Tune those first; a pigment target is the
  fallback.

### 5. Highlight limiters

Creatures, players and bonuses each compress added light before the display
shoulder (`peak / 1.4` in `creature.frag` and `player.frag`; `1.7`, `2.4` in
`bonus.frag`), so dense fights saturate by different rules per material. Keep the
world target display-referred for now and make the tonemap's shoulder
(`hdr_tonemap.frag`) the main compressor, keeping only response curves a material
needs. Beams still blow out even on an HDR display, with moiré along their bright
core: piles of additive light reach hundreds of times white in the half-float world
target, so a limiter belongs before the tonemap, and the moiré may come from
half-float accumulation.

### 6. Smoke bands (an experiment)

Smoke composites after every entity, so the whole volume sits in front of the
world. Try ground, then low smoke, then entities, then high smoke. The client draws
smoke from a hook after the world's sprites; a low band needs a second hook after
the terrain. A low band under top-down sprites can read as baked into the dirt, so
judge it on captures. Add body shadows inside smoke only after profiling: per-pixel
shadow traces are what blew the ion-chain budget before #880.

### 7. Linear color, last and all at once

Several lit passes decode albedo, add light and gamma-encode before the HDR target,
while unlit sprites, additive effects and smoke blend in gamma space as the
original's Direct3D 8 did (the client emulates exactly that). Migrating only the
lit shaders would leave the frame with two conventions, and macOS and Wayland
presentation assume the current gamma-domain frame. Write the color contract
first, then move every world path together, with SDR and HDR comparisons.

A first prototype keeps the whole world in linear light (artwork decoded on load,
encoded once before the tonemap). Without smoke it matches today's frame (44.5
against 44.9 mean luma on a late moment), but today's fluid smoke adds about 66
levels of haze there and only about 3 in linear, and why is not yet understood.
The smoke decides it: find that mechanism before choosing a look.

### Housekeeping

- Late-activation note for the client, as above.

## Later polish

- **Per-species materials.** Chitin with tighter highlights and harder rims; flesh
  with broader highlights and restrained transmission; scales with broken,
  higher-frequency specular; cloth mostly diffuse; brass as tiny warm glints; ice
  with edge Fresnel and thickness tint. Data-driven and approximate; no authored
  normal maps.
- **Emissive-only bloom**, after the baseline and limiters settle: half-resolution,
  driven by tagged emissive sources, never whole-frame luminance; white corpses,
  bright terrain and the HUD never bloom.
- **Wet-ground disturbances**: short, low-contrast wakes or footprints through fresh
  deep blood, small ripples from heavy explosions, glints where casings land.
- **Selective reflections** of large entities on the smoothest fresh pools, only if
  readable and cheap.
- **Packed material channels** before adding more maps; drop unused depth
  attachments.

## Artistic direction

### Keep Crimsonland gritty, not glossy by default

The original art has strong silhouettes, rough terrain, dark blood and small but
legible effects. RTX works best when it gives those shapes depth and
cause-and-effect, worst when every surface becomes a smooth procedural material.
The creature dome normal, painted-luminance relief, thin-part transmission and
bonus clear coat are useful tools; they should not all have equal prominence on
every object.

### Protect the baseline and the gameplay hierarchy

> With no nearby emitter, RTX should preserve Classic's readability and authored
> color unless a specific environment treatment is intentionally enabled.

Effect hierarchy, most important first:

1. player, incoming threats, and aiming information;
2. dangerous projectiles and explosion timing;
3. creatures and bonuses;
4. blood, terrain, smoke, and persistent material detail.

Wet reflections should support weapons and explosions, not turn old blood into a
mirror that competes with live threats. Smoke may obscure the world briefly, but it
should not erase the player or critical warning cues for long.

### Avoid effects that would fight the game

No generalized chromatic aberration, strong film grain, constant camera
distortion, indiscriminate bloom, or a light for every particle. Perks keep their
gameplay roles: Monster Vision is heat that reveals monsters rather than a lamp,
and fire or explosions never wash it out; Sharpshooter's sight keeps its narrow
reflection and scattering rather than broad red light.

## Effect interactions

| Effect or material | Already connected | Still missing |
| --- | --- | --- |
| Muzzle flashes and projectiles | Light ground, creatures, players, bonuses and smoke; wet reflections; restrained tracers; stable budgets with fades; players and bonuses shadow them | Contact shadows under lit players (2) |
| Ion and fire beams | Analytic visible body; one extended source with closed-form ground light; binned shadows at a quarter resolution; smoke scattering; ion arcs | Ice and material-specific response (3) |
| Explosions | Fireball, warm shell, light, pressure refraction, smoke, blast airflow and scorch coordinated | Hot smoke (3); heat on ice and wet ground |
| Blood, corpses, brass, scorch | Ordered coverage, displacement, wetness, aging, absorption, relief, reflections; neutral sky over blood | Saturation (4); footprints later |
| Ice and freeze | Ground ice attenuates blood and changes roughness and height; heat cools frozen monsters | Lit frozen-creature material, shatter glint and steam (3) |
| Creatures and players | Creatures and players cast body-proxy shadows; creatures receive diffuse, specular and transmission, players cloth lighting | Contact shadows under lit players (2); per-species materials (later) |
| Smoke | Density, heat, advection, self-extinction, scattering with the shared beam profile, sight attenuation, blast response | Bands (6); body occlusion after profiling; soot, heat and steam profiles (3) |
| Bonuses | Obsidian shell, foil emblem, clear coat, dynamic reflections; shells cast body shadows | Fewer own limiters (5) |
| Shockwaves | Distort world and smoke together, keep the HUD, reuse explosion shell timing | Optional small wet-surface ripple |
| Radioactive, Monster Vision, Sharpshooter | Distinct responses: a pulsing material light, heat bodies and trails, a narrow sight | Keep their gameplay roles distinct |

## Architecture to aim for

Keep the forward 2D renderer and analytic approximations; a deferred renderer or a
full volumetric system would add complexity without solving the important problems.

- **One presentation descriptor per visual source**: visible geometry and lifetime,
  linear emission, point, segment or annulus shape, height and width, response
  gains and priority, and optional heat, soot, steam and pressure outputs, so the
  visible draw and its light sample the same age and geometry. The explosion
  visual already works this way.
- **One receiver library** (`source_geometry.glsl` is its start): shared source
  evaluation and body visibility, with each material deciding only its response.
- **Frame order**: terrain targets in stamp order; visible sources with stable
  budgets; body occlusion; ground; low smoke; entities; high smoke; pressure
  fronts and, later, emissive bloom; one tonemap; then the HUD.

Python is the single shader source for both clients (`crimson-core/client/shaders.py`
translates it to WGSL), so each of these lands in all three renderers at once.
