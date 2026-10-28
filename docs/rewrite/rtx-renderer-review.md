---
tags:
  - rewrite
  - rendering
  - review
---

# RTX renderer review

Reviewed: 2026-10-23. Updated: 2026-10-28, after follow-up reviews, measurements on
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
share a light list, but each still limits highlights its own way, and some passes
behave like separate layers.
The direction stays:

1. **Preserve the original art: albedo, silhouettes and readability.**
2. **Make Classic-with-no-dynamic-light the reference, then add RTX energy.**
3. **One source model across every receiver.**
4. **Spend new work on cross-effect interactions, not more isolated glow.**
5. **Keep gameplay readability ahead of physical purity.**

## Shipped

| What | Where | Result |
| --- | --- | --- |
| Comparison tooling | #882 | `crimson replay render --rtx`; golden scenes in `tools/rtx/scenes.toml` captured classic and RTX by `tools/rtx/golden.py`; native client GPU time per pass (since folded into `CRIMSON_PROFILE`, #915) and exact-tick captures (`CRIMSON_CAPTURE_TICK`) |
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
| Render size cap | #913 | The RTX world draws at most at twice the game's resolution (the terrain's density) and is scaled up on present; the HUD stays native. `rendersize` raises or lowers the cap. Fullscreen on a large display stopped stuttering |
| Frame profiles | #915, #916, #922, #926 | `CRIMSON_PROFILE` writes one record per frame (CPU and GPU per pass, draws, scene sizes, targets) and `tools/profile.py` slices it (`summary`, `worst`, `compare`, `timeline`). The GPU is timed on every 8th frame: on macOS each timer query flushes the driver, which made a fake 6 to 8 ms stall in the players pass. Records come out in frame order and keep their GPU times |
| Light reach | #917 | The ground skips each light where neither its light nor its reflection reaches, before any of its work: about 2 ms of the late-game ground, pixel-identical |
| Decal bakes pass by pass | #918, #921 | The native client stamps a bake's marked decals into each terrain companion in turn, each bound once: a seek's bake 25 to 33% faster. #921 fixed the terrain left unbound after a wetness rebase |
| Creature shadows at quad corners | #919, #923 | Creature visibility is traced at each quad's corners and interpolated: a Nuke over a late crowd went from about 50 to 29 ms of GPU. #923 culls a light only when it misses the whole quad, so corner shadows no longer pop |
| GL submission state | #924 | The native client caches uniform locations, uniform values and sampler state and reuses one quad index buffer: in the dense-beams window, uniform calls drop from about 1,600 to 440 a frame and sampler calls from 680 to 24. CPU submission only, no frame-rate change claimed |
| Coarse visibility atlas | #925, #927 | Every ground shadow comes from one world-anchored atlas at four world units a texel, four lights a texel, drawn before the HDR world; the ground pass walks no body grid. Beams keep their directional penumbrae. Reflections share the direct light's mask (an intended approximation that supersedes #923's reflection rule), and turning shadows off also clears reflection occlusion. Late Survival frames 10.8 to 9.7 ms (9 to 11% in paired runs); golden scenes differ only at soft shadow edges |
| Lit freeze ice | #932 | The freeze's cubes and the shatter's cubes and shards are lit as ice instead of stamped unlit. `tools/rtx/ice_surface.py` recovers a surface from the original sprite: the cube's render camera and bent, rounded body fitted to its corners, outline and shading, domes for the shards, and on each a height field matching the sprite's relative shading, with the mottling that leaves. Lights glint off the ice and shade it blue, and it keeps the original's look unlit. Cubes over frozen bodies let them show through their dark faces; the shatter stays solid. Monster Vision shows no heat on frozen monsters, which read as themselves inside the ice |
| Hot smoke | #933 | Sources deposit heat by profile (`SOURCE_HEAT`); heat cools faster than smoke thins, so heat per unit of smoke is its age. Fresh explosion smoke glows yellow-orange through deep red to gray within about a second, rocket trails for their first instants; muzzle and old smoke never glow, and the glow lights nothing else |
| Flame soot | #934 | Each flame particle that burns out leaves a small, faint puff of soot, warm enough to glow dimly for a moment. The flame sprites stay: a fluid flame of hot gas swirled well but read redder and dimmer than the original's yellow-white flame |
| Debug views everywhere | #935, #936 | F6 and Shift+F6 cycle the views under the pause menu too, labelled in the game's font, and in the native and web clients as in Python (`rtxdebug` in their console). A view picked in a paused replay draws the world again; map views keep only the ground's or the smoke's pass |

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
- **Smoke bands.** Ground, low smoke, entities, high smoke: a second hook after the
  terrain and a second composite, for smoke under top-down sprites that reads as
  baked into the dirt. Smoke stays one layer over the world.
- **Bodies shadowing the smoke.** Each smoke light read its mask from the ground's
  visibility atlas where the ray through the smoke met the ground. It worked (shafts
  past bodies in the smoke-light view, up to 40 levels) but shaded frames were
  unchanged on every golden scene and four late-game moments: the smoke's look is
  mostly its sky fill, and the weapon light it scatters is too small for shadows in
  it to show. It cost the smoke pass up to 0.4 ms.
- **Shatter steam.** The fluid carries density, heat and velocity, no color, so a
  cold puff where the ice breaks draws as the same gray smoke and reads as dust,
  not frost; a white vapor would need another channel through every smoke pass.
  Freeze shatters whole crowds at once, so the puffs would fog the screen just as
  the shards should read, and the lit ice already carries the moment.
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
- **Reading CPU frame time with GPU timers on.** On macOS each timer query flushes
  the driver, which inflates the CPU's frame time and showed as a stall in the pass
  after the ground. Profiles time the GPU on every 8th frame (#916); compare wall
  times untimed (`CRIMSON_PROFILE_GPU=0`) and only between builds that both sample.
- **Dropping the original's drop shadows in RTX.** Players draw a darkened copy of
  their sprite at 35% one pixel down and right, creatures one at 40% while shadows
  are on and Monster Vision is off, under the RTX body shadows. Off, the golden
  scenes change in 20,000 to 114,000 pixels by up to 89 levels, nearly all
  creatures', and bodies float: the drop shadows are what ground them, and the
  body shadows are faint beside them. Kept as the original draws them.
- **Light through the ice.** Under many lights, transmission outweighed the faces and
  flattened every cube into a grey pillow. Ice only glints and scatters a little.
- **Procedural ice.** A raymarched cube with chipped corners, tumbling with each
  piece's turn, read as 3D but as glass or plastic, not the original's chunky ice.
  The surface recovered from the sprite keeps its silhouette and fractures.
- **Mostly clear ice.** Opacity following the sprite's brightness (dark faces near
  0.4) with a cyan scatter inside let frozen bodies show, but cubes turned ghostly,
  the shatter nearly vanished and the tint barely showed. Only cubes over bodies
  got a partial window, to about 0.55.
- **Exact ground restructurings.** Each branch building only the geometry it reads,
  reusing the beam frame, skipping zero-density and head-only integral terms,
  returning early from fully lit visibility bins and skipping the fluid normal's
  material taps on dry pixels all measured no faster: the shader compiler already
  drops the dead work, and late-game ground is mostly blood.

## Remaining, in priority order

### 1. What is left of the late-game frame

Profiles of a late Survival run (Run 26 around ticks 41000 and 47000, RTX at 2048×1536 on an M1 Pro) after #925: frames
take about 9.7 ms, GPU-bound at about 8.2 ms, the CPU waiting at the swap. The ground's shading is about 5.9 ms of it
and its visibility atlas 0.15 ms; the smoke solver (0.8 ms) and everything else are small. Probes on master
(2026-10-27, two rounds) split the shading:

| Part | Cost |
| --- | --- |
| The material with no lights | 0.9 ms |
| Beams' direct light | 1.4 ms |
| Reflections | 0.9 ms |
| The rest of the per-light loop (reach tests, discs' and rings' direct light, atlas reads) | about 2.7 ms |

Timings move by tens of percent between runs: compare paired, alternating runs.

Next, in order of what they could save:

- **Per-tile light lists.** The per-light loop is now the largest part. Bin the lights into 32×32-pixel tiles (one
  bit per light, an RGBA8 texture) so a pixel only visits the lights that reach its tile.
- **The beams' light at a lower resolution.** A prototype before #925 summed the beams' light (shadowed) and an
  energy-weighted direction at a quarter of the resolution, stored as flat ground receives it, and the ground scaled
  it by its own relief: within 0.16 of 255 on the golden scenes, 0.4 to 0.7 ms faster late in a run. It needs
  rebuilding on the atlas; beams' direct light now costs 1.4 ms, which bounds it.
- **Reflections at a lower resolution**, bounded by their 0.9 ms.
- **A half-float surface target**, for bandwidth.

The CPU's own work matters where the CPU limits (the browser). #924 caches the native client's uniforms and
samplers. Left:

- **Submission.** Shared light uniforms across passes, batched beams and effects, fewer smoke submissions; the
  WebGPU client still stamps each decal as it lands instead of pass by pass.
- **CPU stalls.** The viewer's frame hold copies the back buffer every frame, and smoke switches framebuffers per
  slice.
- **Light selection and the body grid** are built on the CPU every frame.

Also:

- **Coarse shadow edges.** The atlas's texel is four world units (eight pixels at twice the game's resolution), so
  blockers thinner than a texel lose their contact shadow. In motion it holds: 60 consecutive frames of a crowd
  under Fire Bullets, matched tick for tick against the build before #925, jitter as much from frame to frame (0.89
  against 0.90 levels on average). If edges show in play, try an edge-aware upsample.
- **Non-finite direct light.** #931: the beams' falloff took `asinh` of thousands beside a beam's axis, which the
  GL driver cancels to `log(0)`; 252 dark specks across the golden scenes, none after.

### 2. Bodies push the smoke

Smoke flows around nothing that walks through it: a crowd charging through a cloud
leaves it untouched, while every projectile already stirs a wake (`AtmosphereImpulse`).
Each tick, give moving bodies a wake of their own along their path, sized by the
body and scaled by its speed, under its own budget so a swarm cannot starve blasts,
muzzle jets or shots. It moves the smoke itself, so it shows wherever smoke is; judge
it on crowd scenes and time the solver before and after.

### 3. The unlit baseline (a decision, made from captures)

- **Ambient level.** The ground ambient was cut from 0.94 to 0.50 in #813 so weapon
  light reads against it; unlit RTX ground is now noticeably darker than Classic.
  Whether to raise it is an art call to settle on the golden scenes. Either way,
  `rtx-rendering.md` still says unlit terrain keeps its Classic brightness, which is
  out of date.
- **The sky over wet ground.** #882 made it neutral gray over blood, since the cool
  blue read magenta there, and gray read flat. #930 makes it cyan at 1.5× its
  luminance, picked in play from gray, blue and cyan: cyan over red sums toward
  white instead of magenta.
- **Blood saturation.** With the hue fixed, RTX blood is still grayer than Classic's
  deep red (red about three times green, against four to six in Classic), from the
  gray sheen and wet-soil darkening. Tune those first; a pigment target is the
  fallback.

### 4. Highlight limiters

Creatures, players and bonuses each compress added light before the display
shoulder (`peak / 1.4` in `creature.frag` and `player.frag`; `1.7`, `2.4` in
`bonus.frag`), so dense fights saturate by different rules per material. Keep the
world target display-referred for now and make the tonemap's shoulder
(`hdr_tonemap.frag`) the main compressor, keeping only response curves a material
needs. Beams still blow out even on an HDR display, with moiré along their bright
core: piles of additive light reach hundreds of times white in the half-float world
target, so a limiter belongs before the tonemap, and the moiré may come from
half-float accumulation.

### 5. Linear color, last and all at once

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
  higher-frequency specular; cloth mostly diffuse; brass as tiny warm glints.
  Data-driven and approximate; no authored normal maps.
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
| Muzzle flashes and projectiles | Light ground, creatures, players, bonuses and smoke; wet reflections; restrained tracers; stable budgets with fades; players and bonuses shadow them | - |
| Ion and fire beams | Analytic visible body; one extended source with closed-form ground light; directional shadows from the coarse visibility atlas; smoke scattering; ion arcs | Material-specific response (later) |
| Explosions | Fireball, warm shell, light, pressure refraction, smoke and its heat glow, blast airflow and scorch coordinated | Heat on ice and wet ground |
| Blood, corpses, brass, scorch | Ordered coverage, displacement, wetness, aging, absorption, relief, reflections; cyan sky over blood | Saturation (3); footprints later |
| Ice and freeze | Ground ice attenuates blood and changes roughness and height; the freeze's cubes and shatter lit as ice; frozen bodies show through their cubes, without Monster Vision's heat | - |
| Creatures and players | Creatures and players cast body-proxy shadows over the original's drop shadows; creatures receive diffuse, specular and transmission, players cloth lighting | Per-species materials (later) |
| Smoke | Density, heat by source with a glow while fresh, flame soot, advection, self-extinction, scattering with the shared beam profile, sight attenuation, blast response | Bodies pushing it (2) |
| Bonuses | Obsidian shell, foil emblem, clear coat, dynamic reflections; shells cast body shadows | Fewer own limiters (4) |
| Shockwaves | Distort world and smoke together, keep the HUD, reuse explosion shell timing | Optional small wet-surface ripple |
| Radioactive, Monster Vision, Sharpshooter | Distinct responses: a pulsing material light, heat bodies and trails, a narrow sight | Keep their gameplay roles distinct |

## Architecture to aim for

Keep the forward 2D renderer and analytic approximations; a deferred renderer or a
full volumetric system would add complexity without solving the important problems.

- **One presentation descriptor per visual source**: visible geometry and lifetime,
  linear emission, point, segment or annulus shape, height and width, response
  gains and priority, and optional heat, soot and pressure outputs, so the
  visible draw and its light sample the same age and geometry. The explosion
  visual already works this way.
- **One receiver library** (`source_geometry.glsl` is its start): shared source
  evaluation and body visibility, with each material deciding only its response.
- **Frame order**: terrain targets in stamp order; visible sources with stable
  budgets; body occlusion; ground; entities; smoke; pressure
  fronts and, later, emissive bloom; one tonemap; then the HUD.

Python is the single shader source for both clients (`crimson-core/client/shaders.py`
translates it to WGSL), so each of these lands in all three renderers at once.
