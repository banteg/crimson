✅ Unpacked `crimson-2026-01-31.zip` and compared **src/** against the **authoritative decompile in analysis/** (mainly `analysis/ghidra/raw/crimsonland.exe_decompiled.c`). Below is a weapon‑parity report focused on **high‑fidelity behavior**.

I’ll structure this as:

1. **Confirmed mismatches (your eyeballed ones + what I found)**
2. **Root causes (exact src locations)**
3. **What original does (decompile references)**
4. **Recommended fixes (actionable)**
5. **Other weapon logic parity scan**
6. **Player speed parity**

---

# 1) ✅ Confirmed mismatches (your list)

## A) Flame weapons: “spawns 360°”

### ✅ Confirmed

In `src/crimson/gameplay.py`, flame weapons spawn particles using `dir_angle`, which is a **random 0..2π** helper used for aim jitter. That makes flame particles shoot in arbitrary directions.

**src culprit**

* `player_fire_weapon()` uses:

```py
state.particles.spawn_particle(... angle=dir_angle ...)
```

for:

* Flamethrower
* Blow Torch
* HR Flamer

📍 File: `src/crimson/gameplay.py`
📍 Block: weapon branch handling around the flame weapon cases (grep `WeaponId.FLAMETHROWER`, `BLOW_TORCH`, `HR_FLAMER`)

### What original does

Decompile uses:

```c
fVar14 = aim_heading - 1.5707964;
fx_spawn_particle(&muzzle_pos, fVar14, ...);
```

So **always forward along aim**, not random.

📍 Decompile reference: `player_update()` firing logic around the Flamethrower / Blow Torch / HR Flamer cases (you can see it near where it sets `fVar14 = aim_heading - pi/2`).

### Also: Blow Torch / HR Flamer style_id missing

Original sets particle style IDs after spawning:

* Blow Torch → `style_id = 1`
* HR Flamer → `style_id = 2`

In our version, `ParticlePool.spawn_particle()` always sets `style_id = 0`, and gameplay never overrides it. This makes Blow Torch behave visually like Flamethrower.

---

## B) Rocket weapons: “stubs in arsenal view”

### ✅ Confirmed

Renderer draws secondary projectiles as **circles** instead of textured/rotated rocket sprites with glow/trails.

📍 File: `src/crimson/render/world_renderer.py`
Function:

```py
def _draw_secondary_projectile_pool(...)
```

It uses:

```py
rl.draw_circle(...)
```

Only.

### What original does

Original draws rockets as textured quads using the projectile atlas frame `(grid=4, frame=3)` with rotation + glow + optional detail sprite effects.

Secondary projectile rendering is clearly present in decompile (you can see it binding the projectile texture and doing `grim_set_atlas_frame(4,3)`).

So: **arsenal preview will absolutely look stubby** until `_draw_secondary_projectile_pool` is updated.

---

## C) Pulse Gun: wrong color + should vary in size

### ✅ Confirmed

Our Pulse Gun rendering currently:

* uses the right atlas frame `(grid=2, frame=0)` ✅
* but uses an incorrect tint (bluish gray) ❌
* and uses constant size ❌ (doesn’t scale with distance travelled)

📍 File: `src/crimson/render/world_renderer.py`
Inside `_draw_projectile()` special-casing for `ProjectileTypeId.PULSE_GUN`

### What original does (important detail)

Pulse in-flight (`life_timer == 0.4`) scales based on distance from origin:

```c
dist = distance(origin, pos);
scale = dist * 0.01;
size = scale * 16; // grows as it travels
color = (0.1, 0.6, 0.2, alpha*0.7) // green
```

On fade (`life_timer < 0.4`) it draws a fixed 56×56 white flash that fades.

📍 Decompile reference: projectile_render around `PROJECTILE_TYPE_PULSE_GUN`

✅ Your knockback note: correct — I didn’t see a mismatch in our hit impulse logic; it appears consistent with how the original pushes targets.

---

## D) Ion hit decals / effects: completely wrong

### ✅ Confirmed

We currently add a **blue fx_queue floor decal** for all `BEAM_TYPES`:

📍 File: `src/crimson/game_world.py`
Function `_queue_projectile_decals()`:

```py
elif projectile.type_id in BEAM_TYPES:
    self.fx_queue.add(effect_id=0x01, color=(0.7,0.9,1.0,1.0))
```

This is not what the original does.

### What original does

On ion hit, the original spawns:

* `FUN_0042f270()` → a **ring burst** (effect_id=1)
* `FUN_0042f540()` → a **scaled burst cloud** (effect_id=0)

with different params per weapon:

Ion Minigun:

```c
FUN_0042f270(pos, 1.5, 0.1);
FUN_0042f540(pos, 0.8);
```

Ion Rifle:

```c
FUN_0042f270(pos, 1.2, 0.4);
FUN_0042f540(pos, 1.2);
```

Ion Cannon:

```c
FUN_0042f270(pos, 1.0, 1.0);
FUN_0042f540(pos, 2.2);
```

✅ These are **EffectPool** style effects (rings / bursts), not fx_queue ground decals.

📍 Decompile reference: `projectile_update()` ion hit branch

---

## E) Ion cannon projectile size wrong

### ✅ Confirmed (big mismatch)

Our beam drawing uses small constant-ish scaling.

Original is *dramatically* larger for ion cannon on “impact/fade” stage:

* Ion Minigun → scale `1.05`
* Ion Rifle → scale `2.2`
* Ion Cannon → scale `3.5` (!!)

and then uses `size = scale * 32` meaning ion cannon flare can be ~112px wide.

📍 Decompile reference: projectile_render branch for `(ION_RIFLE|ION_MINIGUN|ION_CANNON|FIRE_BULLETS)` when `life_timer != 0.4`

So yes — ion cannon looks too small in our renderer.

---

# 2) Fire Bullets vs weapon clip (“works wrong with some weapons”)

### ✅ Partially correct already

Our code correctly does **NOT subtract ammo** while Fire Bullets is active:

```py
if player.fire_bullets_timer <= 0.0:
    player.ammo -= ammo_cost
```

### ❌ But still mismatches original in 2 ways

## (1) We block firing if ammo==0 even in fire bullets mode

At the top of `player_fire_weapon()`:

```py
if player.ammo <= 0.0 and not firing_during_reload:
    player_start_reload(...)
    return
```

This runs even when fire bullets is active.
In the original, the “ammo <= 0 → start reload” check happens after firing, meaning fire bullets can still fire even if the weapon is empty *that frame*.

So you can get weird behavior where fire bullets feels “tied to clip state.”

## (2) Spread heat logic is wrong in fire-bullets mode

Original always adds spread heat based on the **fire bullets weapon spread heat**, not the current weapon (even for multi‑pellet weapons).

In our code:

* for pellet_count==1 → uses fire bullets spread heat ✅
* else → uses weapon spread heat ❌

📍 File: `src/crimson/gameplay.py` inside the fire bullets branch

---

# 3) Player default speed (“feels faster”)

### ✅ Confirmed

Our movement is currently:

📍 File: `src/crimson/gameplay.py`

```py
speed = 120.0 * speed_multiplier
```

Default `PlayerState.move_speed_multiplier = 2.0`, so baseline movement is ~240 units/s.

### What original does

Original velocity magnitude is:

```
speed = move_speed * speed_multiplier * 25.0
```

* `move_speed` accelerates up to **2.0** normally
* or **2.8** with Long Distance Runner perk
* heavy weapon (Mean Minigun) clamps move_speed to **0.8**

So baseline max speed is:

* normal: `2.0 * 25 = 50`
* with runner perk: `2.8 * 25 = 70`
* Mean Minigun clamp: `0.8 * 25 = 20`

✅ So yes: our default speed is ~4.8× too fast.

---

# 4) Additional weapon parity findings (not in your list)

## Plasma Shotgun ammo consumption is wrong

In our `player_fire_weapon()`:

📍 File: `src/crimson/gameplay.py`
The Plasma Shotgun branch does:

```py
ammo_cost = player.ammo
player.ammo = 0.0
```

But the original Plasma Shotgun consumes **1 ammo per shot**, not the entire clip. It fires 14 plasma-minigun pellets but does not dump the clip.

📍 Decompile: Plasma Shotgun case does not overwrite `local_38` (ammo cost remains 1.0)

This is a real gameplay parity mismatch.

---

# 5) “Check all other weapons logic”

### High-level summary

Most weapon firing patterns are correctly mirrored: special cases implemented match the decompile set:

* Multi‑Plasma ✅ (correct 5-shot split with correct spreads)
* Rocket Launcher / Seeker / Rocket Minigun / Swarmers ✅ (use secondary pool)
* Plasma Shotgun ✅ spread/speed randomization (but ammo cost ❌)
* Gauss Shotgun ✅ (6 pellets, correct jitter factor)
* Ion Shotgun ✅ (8 pellets ion rifle type, correct jitter factor)
* Bubblegun ✅ uses slow particles

Big remaining parity gaps outside “logic” are mostly **render/effects parity**:

* missing rocket trails + glow
* missing secondary explosion flare rendering
* missing ion hit ring/burst functions
* missing pulse scaling
* missing certain projectile render special cases (ion/fire bullets look)

---

# 6) Recommended fixes (targeted, faithful)

### 🔥 Flame weapons

✅ Fix angle: use `player.aim_heading - pi/2` not `dir_angle`.

✅ Also set particle `style_id` after spawn for Blow Torch and HR Flamer, matching decompile:

* Blow Torch: style_id=1
* HR Flamer: style_id=2

This will require `spawn_particle()` to return the index (like original) or another way to access last spawn.

---

### 🚀 Rockets

✅ Update `_draw_secondary_projectile_pool()` to:

* draw atlas sprite `(grid=4, frame=3)`
* rotate by heading
* add glow quad (optional, fidelity)
* add trail sprite effects (optional but important, fidelity)

---

### 💚 Pulse Gun

✅ Render in-flight size based on distance traveled:
`size = distance(origin,pos) * 0.16`

✅ Tint should be green: `(0.1, 0.6, 0.2, alpha*0.7)`

✅ Fade stage should draw 56×56 white flash fading by `min(life_timer*2.5,1)`

---

### ⚡ Ion hit effects / “decals”

✅ Remove BEAM_TYPES entry from `_queue_projectile_decals()`
✅ Implement ion-hit burst effects in projectile hit path using EffectPool equivalents of:

* `FUN_0042f270` (ring)
* `FUN_0042f540` (scaled burst cloud)

---

### 🔥 Fire Bullets clip interaction

✅ Allow firing even if ammo==0 when fire bullets active (remove early return gating in that case)

✅ Spread heat: always use fire-bullets spread heat increment, regardless of pellet count.

---

### 🏃 Player speed

✅ Replace `120.0` base constant with `25.0`
…and ideally port `move_speed` accel/decel system (including Mean Minigun clamp and runner perk cap), since the original is not a flat speed.

---

# What I didn’t fully complete (yet)

You asked “check all weapons logic” — I reviewed the **firing logic parity** and caught the major mismatch (Plasma Shotgun clip dump) plus confirmed all your listed issues. I did not exhaustively verify every single **projectile_update behavior** for every weapon type beyond the ion/pulse/rocket/flame/fire‑bullets areas, but the main “logic” divergences uncovered are those above.

If you want, I can also produce a **weapon-by-weapon parity table** (weapon id → expected behavior → current src behavior → mismatch notes) generated by scanning the weapon table + fire logic.

---

## Quick “Most Impactful Fix Order” ⭐

If you want the fastest route to “feels like original”:

1. **Player speed** constant (120→25) + minigun clamp
2. **Flame angle** (dir_angle→aim_heading-pi/2)
3. **Pulse Gun render** (color + scaling)
4. **Ion hit effects** (ring/burst) + remove wrong fx_queue decal
5. **Ion cannon projectile size** (scale constants)
6. **Secondary projectile render** (rocket sprite + rotation)

---

If you’d like, I can draft a patch diff for the core gameplay fixes (flame angle + plasma shotgun ammo + fire bullets gating + movement constant) and separately a renderer patch (secondary projectile sprites + pulse/ion render).
