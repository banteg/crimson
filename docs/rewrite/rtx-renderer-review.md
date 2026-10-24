---
tags:
  - rewrite
  - rendering
  - review
---

# RTX renderer review

Reviewed: 2026-10-23. Updated: 2026-10-24, after follow-up reviews, measurements on
the golden scenes, and the work they led to.

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
| Monster Vision | #884, #885 | Heat instead of a lamp: ironbow bodies keyed to Monster Vision's fade (Hidden Evil's near-invisible aliens show in full) and fading world-space trails, in Python and both clients; the aura's ground light is gone |

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

## Remaining, in priority order

### 1. Stable light selection

`select_material_lights` (`src/crimson/render/rtx/material_lights.py`, and
`crimson-core/game/rtx_lights.cpp` in the client) ranks sources by brightness,
gain and distance to the view center and keeps independent top-N sets, with no
temporal stability. In dense fights a source crossing the cutoff drops its ground,
body, reflection and smoke response at once.

- Give sources stable identities (projectile slot and type, explosion record,
  flame cell) and rank by contribution to the visible receivers.
- Add hysteresis or a short fade per budget, advanced per tick, not per frame, so
  the picture does not depend on frame rate and native/web comparisons stay exact.
- Clear it on seeks and restores (the client's reset hook already exists).
- Keep deterministic tie-breaking; reserve semantic slots only where captures show
  the need. Test more than 32 sources while the camera pans.

### 2. Players and bonus shells as shadow casters

Only creature bodies enter the occlusion grid; players and bonus shells receive
light but cast nothing, and `player.frag` and `bonus.frag` skip body visibility.
Add one body per player and per bonus shell to `build_occlusion_grid` (and
`rtx_build_occlusion` in the client), with the self-exclusion creatures already
use. Then keep only a restrained contact-shadow part of the native blob shadow
where dynamic lights take over, so lit areas do not show a pasted-on double shadow.

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
needs.

### 6. Smoke bands (an experiment)

Smoke composites after every entity, so the whole volume sits in front of the
world. Try ground, then low smoke, then entities, then high smoke. The client draws
smoke from a hook after the world's sprites; a low band needs a second hook after
the terrain. A low band under top-down sprites can read as baked into the dirt, so
judge it on captures. Add body shadows inside smoke only after profiling: per-pixel
shadow traces are what blew the ion-chain budget before #880.

### 7. Ground pass cost

The ground pass is most of RTX's GPU time in every golden scene, from about 3 ms in
the quiet ones to about 16 ms in the densest, against about 2 ms for a whole
Classic frame. Profile with `CRIMSON_GPU_TIMERS` before and after each change.

### 8. Linear color, last and all at once

Several lit passes decode albedo, add light and gamma-encode before the HDR target,
while unlit sprites, additive effects and smoke blend in gamma space as the
original's Direct3D 8 did (the client emulates exactly that). Migrating only the
lit shaders would leave the frame with two conventions, and macOS and Wayland
presentation assume the current gamma-domain frame. Write the color contract
first, then move every world path together, with SDR and HDR comparisons.

### Housekeeping

- A Python-vs-client RTX frame diff. #885 compared one golden scene by hand
  (heat pixels within about five levels); a tool would make it routine.
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
| Muzzle flashes and projectiles | Light ground, creatures, players, bonuses and smoke; wet reflections; restrained tracers | Stable budgets (1); player and bonus occlusion (2) |
| Ion and fire beams | Analytic visible body; segment lighting with one shared profile; continuous ground response; projected shadows; smoke scattering; ion arcs | Ice and material-specific response (3) |
| Explosions | Fireball, warm shell, light, pressure refraction, smoke, blast airflow and scorch coordinated | Hot smoke (3); heat on ice and wet ground |
| Blood, corpses, brass, scorch | Ordered coverage, displacement, wetness, aging, absorption, relief, reflections; neutral sky over blood | Saturation (4); footprints later |
| Ice and freeze | Ground ice attenuates blood and changes roughness and height; heat cools frozen monsters | Lit frozen-creature material, shatter glint and steam (3) |
| Creatures and players | Creatures cast body-proxy shadows and receive diffuse, specular and transmission; players receive cloth lighting | Players as occluders and contact shadows (2); per-species materials (later) |
| Smoke | Density, heat, advection, self-extinction, scattering with the shared beam profile, sight attenuation, blast response | Bands (6); body occlusion after profiling; soot, heat and steam profiles (3) |
| Bonuses | Obsidian shell, foil emblem, clear coat, dynamic reflections | Shadows and contact (2); fewer own limiters (5) |
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
