Here’s what I found in the repo, what the original executable actually does, and a concrete “do this / change that” plan to get **Fire Bullets**, **Plasma (rifle/minigun/cannon + spider plasma + shrinkifier)**, and **Ion weapons** rendering (and Splitter hit SFX) aligned to the classic game.

---

## What’s wrong right now (in `src/`)

### 1) Plasma projectiles are basically unimplemented

In `src/crimson/render/world_renderer.py::_draw_projectile`, plasma types **don’t have a sprite mapping**, so they fall through to the fallback `draw_circle()` “pink dot” rendering.

That’s why **Plasma Rifle / Plasma Minigun / Plasma Cannon** look totally wrong.

### 2) Ion + Fire Bullets are rendered as a generic “beam segments” hack

Right now `_draw_projectile()` does:

```py
if type_id in BEAM_TYPES and proj.life_timer >= 0.4:
    # draw repeated atlas sprites along origin->pos
    return
```

This causes multiple problems:

* It draws **only** a repeated-sprite strip, with fixed spacing/scale.
* It **skips** the correct head glow / color scheme the original uses.
* On hit/fade (`life_timer < 0.4`) Ion should still render a fading beam and **do chain arcs** to nearby creatures; we currently just draw a single sprite with alpha.

### 3) Fire Bullets is missing its extra “flame blob” overlay

The original draws an **additional** particle sprite (from `particles.png`, effect id `0x0D`) on Fire Bullets projectiles while they’re flying. We don’t.

### 4) Splitter gun has wrong *hit* SFX (not shot SFX)

`src/crimson/audio_router.py::_hit_sfx_for_type()` currently decides shock-hit vs bullet-hit using `BEAM_TYPES`. Since `BEAM_TYPES` incorrectly contains Splitter, Splitter impacts are routed to `shock_hit_01`.

The original decides shock-hit vs bullet-hit by **ammo_class == 4** (electric), not by “beam-ness”. Splitter isn’t electric, so it should use **bullet_hit_0X**.

---

## What the original game does (authoritative behavior)

All of this is in the decompile of `projectile_render @ 0x00423b40`:

* `analysis/ghidra/raw/crimsonland.exe_decompiled.c` around the plasma block (~20300+) and Ion/Fire block (~20590+), plus the Fire Bullets overlay later.

### Plasma rendering (types: `0x09`, `0x0B`, `0x1C`, `0x1A`, `0x18`)

The original **binds `particles_texture`** and uses **`effect_select_texture(0x0D)`** (same atlas entry you already have in `effects_atlas.py`), then draws:

* a short tail (few small quads),
* a head glow (bigger quad),
* and optionally (if `config_fx_detail_flag1` / `reserved0[0x10]` is enabled) an extra 120×120 aura quad.

Colors/sizes differ per plasma type; details below.

### Ion & Fire Bullets rendering (types: `0x15`, `0x16`, `0x17`, `0x2D`)

The original uses `projs.png` atlas, primarily frame **(4,2)**, and draws:

* **a gradient “streak”** along the last **256 units** of the projectile path,
* then a head glow,
* for **Ion** when `life_timer != 0.4` it also draws:

  * a small 32×32 core at the impact point,
  * **chain arcs** to nearby creatures using **manual UV override** (the `docs/atlas.md` “beam/chain” UV points),
  * plus a small glow at each chained creature.

### Fire Bullets overlay

Later in `projectile_render`, the original re-binds `particles_texture`, `effect_select_texture(0x0D)`, and for `type_id == 0x2D` with `life_timer == 0.4` draws a **64×64** rotated quad at the projectile position (white, alpha = global alpha).

---

## Detailed plan: fixes to apply

## Progress

- [x] A) Fix classification constants (stop overloading `BEAM_TYPES`)
- [x] B) Implement Plasma particle rendering (replaces the pink fallback)
- [x] C) Implement Ion + Fire Bullets streak + ion chain arcs
- [ ] D) Add the Fire Bullets particle overlay (missing pass)
- [ ] E) Fix Splitter hit SFX routing (ammo_class-based like the original)
- [ ] Verification checklist

### A) Fix classification constants (stop overloading BEAM_TYPES)

**File:** `src/crimson/sim/world_defs.py`

1. **Remove** these from `BEAM_TYPES`:

* `BLADE_GUN`
* `SPLITTER_GUN`
* (very likely also remove `SHRINKIFIER`, see below)

Right now `BEAM_TYPES` is doing too much (renderer + audio). It should only represent the “Ion/Fire streak + chain UV effect family”, not “things that look like streaks”.

2. Add a missing projectile id enum:

* add `SPIDER_PLASMA = 0x1A` to `ProjectileTypeId`

3. Create explicit sets so renderer logic is readable and faithful:

* `PLASMA_PARTICLE_TYPES = { 0x09, 0x0B, 0x1C, 0x1A, 0x18 }`
* `ION_TYPES = { 0x15, 0x16, 0x17 }`
* `FIRE_BULLETS_TYPE = { 0x2D }`

(If you want to keep a `BEAM_TYPES`, redefine it as `ION_TYPES | FIRE_BULLETS_TYPE`, *not* “blade/splitter”.)

**Why:** this simultaneously fixes the Splitter hit SFX routing and prevents the renderer from treating Splitter/Blade as beam streaks.

---

### B) Implement Plasma particle rendering (replaces the pink fallback)

**File:** `src/crimson/render/world_renderer.py`
**Function:** `_draw_projectile()`

Add a plasma branch *before* the current `KNOWN_PROJ_FRAMES` fallback.

#### 1) Use particles texture + effect id `0x0D`

* Texture: `self.particles_texture`
* Atlas selection: use `effects_atlas.EFFECT_ID_ATLAS_TABLE_BY_ID[0x0D]`
* Blend mode: **additive** (`rl.BLEND_ADDITIVE`)
* Rotation: 0 (the original calls `grim_set_rotation(0.0)` for this pass)

#### 2) Tail segment count

The decompile computes an integer `iVar8` from `proj.base_damage` divided by a constant (it does `__ftol()` twice and integer division). You can reproduce exactly by choosing one formula and matching visuals; the simplest faithful reconstruction is:

* `seg = int(proj.base_damage) // 5`  (very plausible: constant 5 shows up in surrounding render code)
* then clamp per type:

  * `0x09` plasma rifle: `seg = min(seg, 8)`
  * `0x0B` plasma minigun: `seg = min(seg, 3)`
  * `0x1C` plasma cannon: `seg = min(seg, 18)`
  * `0x1A` spider plasma: `seg = min(seg, 3)`
  * `0x18` shrinkifier: `seg = min(seg, 3)`

(If after implementing you visually see too many/few tail quads, the divisor is the only knob to adjust; everything else below is straight from the decompile.)

#### 3) Tail spacing, sizes, colors

All of these are explicitly visible in the decompile:

Compute tail direction as:

* `dx = cos(proj.angle + pi/2)`
* `dy = sin(proj.angle + pi/2)`
  (this points *backwards* along travel direction)

Then spacing multiplier by type:

* Plasma rifle `0x09`: spacing = `2.5`
* Plasma minigun `0x0B`: spacing = `2.1`
* Spider plasma `0x1A`: spacing = `2.1`
* Shrinkifier `0x18`: spacing = `2.1`
* Plasma cannon `0x1C`: spacing = `2.6`

Segment sizes by type:

* `0x09`: **22×22**
* `0x0B`: **12×12**
* `0x1A`: **12×12**
* `0x18`: **12×12**
* `0x1C`: **44×44**

Head sizes by type:

* `0x09`: **56×56**
* `0x0B`: **16×16**
* `0x1A`: **16×16**
* `0x18`: **16×16**
* `0x1C`: **84×84**

Colors:

* Tail alpha is always `alpha * 0.4` in this block.
* Plasma rifle (`0x09`) and plasma minigun (`0x0B`) are **white**.
* Spider plasma (`0x1A`) is **green** `(0.3, 1.0, 0.3)`.
* Shrinkifier (`0x18`) is **blue** `(0.3, 0.3, 1.0)`.
* Plasma cannon (`0x1C`) tail/head are **white**, but its optional aura tint becomes blue (see below).

So:

* Tail color:

  * `0x09`: (1,1,1, alpha*0.4)
  * `0x0B`: (1,1,1, alpha*0.4)
  * `0x1A`: (0.3,1,0.3, alpha*0.4)
  * `0x18`: (0.3,0.3,1, alpha*0.4)
  * `0x1C`: (1,1,1, alpha*0.4)

* Head color (same RGB, alpha = alpha):

  * `0x09`: (1,1,1, alpha)
  * `0x0B`: (1,1,1, alpha)
  * `0x1A`: (0.3,1,0.3, alpha)
  * `0x18`: (0.3,0.3,1, alpha)
  * `0x1C`: (1,1,1, alpha)

#### 4) Optional aura quad (fx_detail_flag1)

When `config_fx_detail_flag1` is enabled (your `config.fx_detail_1`), the original draws an extra aura:

* For Plasma Rifle (0x09) and Plasma Cannon (0x1C): **256×256** centered on the projectile.
* For Plasma Minigun (0x0B), Spider Plasma (0x1A), and Shrinkifier (0x18): **120×120** centered on the projectile.

Aura RGB is:

* white for `0x09`, `0x0B`, and `0x1C`
* green `(0.3,1.0,0.3)` for `0x1A`
* blue `(0.3,0.3,1.0)` for `0x18`

Aura alpha is:

* `alpha * 0.3` for `0x09`
* `alpha * 0.4` for `0x1C`
* `alpha * 0.15` for `0x0B`, `0x1A`, and `0x18`

#### 5) Hit/fade stage for plasma

If `life_timer != 0.4`, the original **does not draw the tail**.
It draws a single 56×56 white quad at the current position with:

* `fade = clamp(life_timer * 2.5, 0..1)`
* color `(1,1,1, fade * alpha)`
* size 56×56

So in your renderer, for plasma types:

* if `proj.life_timer >= 0.4`: draw tail + head (+ optional aura)
* else: draw just the fading 56×56 blob

---

### C) Implement Ion + Fire Bullets streak + ion chain arcs

**File:** `src/crimson/render/world_renderer.py`
**Function:** `_draw_projectile()`

Add a branch for types `{0x15,0x16,0x17,0x2D}` *before* your current `BEAM_TYPES` segment hack, and remove/replace that hack entirely.

#### 1) Streak (life_timer == 0.4)

This is the “in flight” streak block.

* Texture: `self.projs_texture`
* Atlas frame: **(4,2)** for the streak segments and head sprite
* Blend: **additive**
* Streak length limit: only draw the last **256 units**

  * `dist = hypot(pos - origin)`
  * `start = max(0, dist - 256)`
* Step distance:

  * `step = min(scale * 3.1, 9.0)`
* Segment size:

  * `size = scale * 32` (square)
* Segment alpha gradient:

  * For each segment at distance `s` from origin:

    * `t = (s - start) / (dist - start)`  (0..1)
    * `segment_alpha = t * alpha`
* Color:

  * For Fire Bullets (0x2D): `(1.0, 0.6, 0.1, segment_alpha)`
  * For Ion (0x15/0x16/0x17): `(0.5, 0.6, 1.0, segment_alpha)`
* Head sprite:

  * color `(1.0, 1.0, 0.7, alpha)`
  * size same as segments (or slightly larger if you want to match look; original uses `fVar24*32`)

**About `scale`:** In the decompile, the in-flight branch uses `fVar24` but the type-specific constants (1.05/2.2/3.5/0.8) are only visible in the **impact** branch. Most likely in-flight uses a consistent scale ~1.0.
So implement `scale = 1.0` (optionally multiply Ion by perk scale, see below).

#### 2) Fade/impact streak (life_timer != 0.4) for Ion only

When Ion hits, the original still draws a streak but fades it using:

* `fade = clamp(life_timer * 2.5, 0..1)`
* `base_alpha = fade * alpha`
* Segment alpha becomes `t * base_alpha`
* Head alpha becomes `base_alpha`

It also changes the scale by type in this impact mode:

* Ion Minigun (0x16): scale = **1.05**
* Ion Rifle (0x15): scale = **2.2**
* Ion Cannon (0x17): scale = **3.5**
* (Fire Bullets has an impact scale too, **0.8**, but Fire Bullets doesn’t normally enter impact mode in your sim; safe to implement anyway.)

So implement:

* if `type_id in ION_TYPES` and `proj.life_timer < 0.4`:

  * `scale = {0x16:1.05, 0x15:2.2, 0x17:3.5}[type_id]`
  * `base_alpha = clamp(proj.life_timer*2.5) * alpha`
  * draw the streak segments using `base_alpha`

#### 3) Ion impact core

Still in Ion impact mode (life_timer != 0.4), after the streak the original draws:

* a **32×32** quad at the projectile position
* color `(0.5, 0.6, 1.0, base_alpha)`

Do that.

#### 4) Ion chain arcs to nearby creatures (the big missing piece)

Still in Ion impact mode, the original chains to creatures in a radius and draws beam quads using **manual UV points**:

From `docs/atlas.md` (and also visible in the decompile):

* UV points:

  * (0) u=0.625 v=0.0
  * (1) u=0.625 v=0.25
  * (2) u=0.625 v=0.25
  * (3) u=0.625 v=0.0

That means: draw a textured quad strip using a fixed vertical slice of the `projs.png` atlas.

**Implementation approach in Raylib:**

* Use `rl.rlSetTexture(self.projs_texture.id)` and `rl.rlBegin(RL_QUADS)` like you already do in `_draw_bullet_trail()`.
* Build 4 vertices for a strip between `p0=projectile_pos` and `p1=creature_pos`:

  * `dir = normalize(p1 - p0)`
  * `perp = (-dir.y, dir.x)`
  * thickness inner = `10 * perk_scale`
  * thickness outer = `14 * perk_scale` (it’s `10 + 4`)
  * draw **two** strips (outer first, then inner) to mimic original’s “bright core + softer outer”
* For each vertex, use UVs listed above (u fixed at 0.625).

**Radius to select targets:**
The decompile’s radius expression is messy because stack vars are reused, but the cleanest faithful way is to mirror **your own sim’s** ion AoE radii (which were derived from the executable):

* Ion Rifle: 88
* Ion Minigun: 60
* Ion Cannon: 128
  Multiply by Ion Gun Master scale if active.

**Number of chained targets:**
The original uses `creature_find_in_radius` with a “start index” and loops; it will draw arcs to multiple targets. In your port, simplest is:

* gather all alive creatures within radius
* sort by distance
* take N (pick a reasonable cap, e.g. 6–10), so visuals are stable and perf-friendly.

**Glow at the target:**
The original draws a quad at each target with the same projs frame (4,2), centered, size ≈ `scale*32`, color `(0.5,0.6,1.0, base_alpha)`.

Do that.

#### 5) Ion Gun Master perk scaling (visual consistency)

In the executable, Ion Gun Master affects electric effects (you already apply it in sim damage radii). In render, it also scales thickness (`fVar25` becomes 1.2).

So:

* compute `perk_scale = 1.2 if any(player has ion_gun_master) else 1.0`
* multiply:

  * arc thickness inner/outer by `perk_scale`
  * arc radius by `perk_scale`
  * (optional) in-flight streak scale by `perk_scale` if you want it to be visibly “stronger”; the decompile only clearly uses it for thickness, but matching the “feel” is reasonable.

---

### D) Add the Fire Bullets particle overlay (missing pass)

**File:** `src/crimson/render/world_renderer.py`
**Function:** `_draw_projectile()`

For `type_id == 0x2D` and `life_timer == 0.4`, after drawing the projs streak:

* bind `particles_texture`
* effect id `0x0D`
* blend additive
* color white `(1,1,1, alpha)`
* **rotation = projectile angle**
* size **64×64**, centered on projectile position

This is exactly the “extra flame blob” pass the executable does in a later pass; doing it inline per projectile is fine as long as you switch blend + texture correctly.

---

### E) Fix Splitter hit SFX routing (ammo_class-based like the original)

**File:** `src/crimson/audio_router.py`

Replace this:

```py
if type_id in BEAM_TYPES:
    return "shock_hit_01"
return random.choice([...bullet_hit...])
```

with:

1. Lookup ammo class from weapon table:

```py
from crimson.weapons import WEAPON_BY_ID
w = WEAPON_BY_ID.get(type_id)
ammo_class = w.ammo_class if w else None
if ammo_class == 4:
    return "shock_hit_01"
return random.choice([...bullet_hit...])
```

2. (Optional) If you want Fire Bullets to be “fire ammo” for UI/logic, set its ammo_class in `weapons.py`:

* Weapon id `45` (`Fire bullets`) currently has `ammo_class=None`
* set to `ammo_class=1` (assuming 1 = fire; consistent with other weapons).

**Why this matters:** Splitter (type_id 0x1D) will stop incorrectly using shock-hit, and you’ll match the exe’s behavior instead of conflating “beam visuals” with “electric ammo”.

---

## Verification checklist (quick, concrete)

After implementing the above, verify with a debug scene that spawns each projectile with a fixed origin/pos:

### Plasma

- [ ] Plasma Rifle (0x09): white 22px tail quads + 56px head, and with fx_detail_1 on you should see a faint 256px aura.
- [ ] Plasma Minigun (0x0B): short white tail (12px) + 16px head, optional 120px aura.
- [ ] Plasma Cannon (0x1C): larger 44px tail quads + 84px head, optional 256px aura.
- [ ] Spider Plasma (0x1A): green tail/head, optional green 120px aura.
- [ ] Shrinkifier (0x18): blue tail/head, optional blue 120px aura.
- [ ] On hit/fade: plasma types should become a **single fading 56×56 white blob** (no tail).

### Ion

- [ ] In flight: blue-ish streak with alpha gradient, head glow more yellow-white.
- [ ] On hit/fade: streak still visible and fading, plus:

  - [ ] 32×32 blue core at impact,
  - [ ] arcs to nearby creatures (textured strips with the `u=0.625` slice),
  - [ ] small glow on targets.
- [ ] Ion Gun Master perk: arcs visibly thicker/reach slightly farther.

### Fire Bullets

- [ ] Orange-ish streak + head glow
- [ ] plus the **additional 64×64 particle overlay** (white, rotated).

### Splitter hit sound

- [ ] Ensure impacts are **bullet_hit_01..06**, not shock_hit.

---

## One more “gotcha” worth calling out

Your current `BEAM_TYPES` set is doing double duty for rendering *and* audio. Even if you don’t implement the full Splitter/Blade render parity right now, **do not use BEAM_TYPES for audio decisions**. The executable uses ammo class. Separating these concerns will prevent a lot of “why does this weapon sound electric?” bugs in the future.

---

If you want, I can also outline (based on the same decompile block you already have) the **correct Splitter and Blade render** (they’re “stretched sprite” effects with capped length and rotation/time-based spin) — your current BEAM_TYPES segment approach is not how the exe draws them — but the steps above address exactly what you flagged: **Fire Bullets + Plasma + Ion rendering, and Splitter SFX**.
