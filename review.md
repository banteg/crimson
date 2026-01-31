# Weapon parity review (progress checklist)

## Status / workflow

- [x] Compared `src/` against the authoritative decompile in `analysis/` (focus: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`).
- [x] Recorded confirmed mismatches + root causes (this doc).
- [x] Implement fixes in `src/`.
- [ ] Verify behavior/visual parity after fixes.
- [ ] Re-scan weapon logic for remaining gaps.

---

## 1) Confirmed mismatches (from review)

### A) Flame weapons: particles “spawn 360°”

- [x] **Confirmed mismatch:** flame weapons spawn particles using random `dir_angle` (0..2π), so they shoot in arbitrary directions.
- [x] **Src culprit:** `player_fire_weapon()` uses:
  ```py
  state.particles.spawn_particle(... angle=dir_angle ...)
  ```
- [x] **Affected weapons:** Flamethrower, Blow Torch, HR Flamer.
- [x] **Where:** `src/crimson/gameplay.py` (weapon branch around `WeaponId.FLAMETHROWER`, `BLOW_TORCH`, `HR_FLAMER`).
- [x] **Original behavior (decompile):** aim-forward angle:
  ```c
  fVar14 = aim_heading - 1.5707964;
  fx_spawn_particle(&muzzle_pos, fVar14, ...);
  ```
- [x] **Verified:** Blow Torch / HR Flamer override particle `style_id` (1/2) after spawn.
- [x] **Fix:** flame particle angle uses aim-forward direction (not random `dir_angle`).
- [x] **Verify:** particles fire forward along aim and style ids match the original mapping.

---

### B) Rocket weapons: “stubs in arsenal view”

- [x] **Confirmed mismatch:** secondary projectiles render as circles.
- [x] **Where:** `src/crimson/render/world_renderer.py` → `_draw_secondary_projectile(...)`.
- [x] **Current behavior:** draws circles when textures are missing.
- [x] **Original behavior (decompile):** textured/rotated rocket quad using atlas frame `(grid=4, frame=3)`; rotation + glow + trail/detail effects.
- [x] **Fix:** render secondary projectiles using atlas sprite `(grid=4, frame=3)` with rotation by heading.
- [x] **Fix (fidelity):** add glow quad.
- [x] **Fix (fidelity):** add trail/detail sprite effects.
- [ ] **Verify:** rockets look correct in arsenal preview (no more circles/stubs).

---

### C) Pulse Gun: wrong color + should vary in size

- [x] **Confirmed mismatch:** tint is wrong (bluish/gray instead of green).
- [x] **Confirmed mismatch:** size is constant (does not scale with distance travelled).
- [x] **Where:** `src/crimson/render/world_renderer.py` → `_draw_projectile()` special case for `ProjectileTypeId.PULSE_GUN`.
- [x] **Original behavior (decompile):** in-flight (`life_timer == 0.4`) scales with distance:
  ```c
  dist = distance(origin, pos);
  scale = dist * 0.01;
  size = scale * 16;
  color = (0.1, 0.6, 0.2, alpha*0.7);
  ```
- [x] **Original behavior (decompile):** on fade (`life_timer < 0.4`), draws a fixed 56×56 white flash that fades.
- [x] **Notes:** knockback behavior looks consistent (no mismatch spotted).
- [x] **Fix:** tint to green `(0.1, 0.6, 0.2, alpha*0.7)`.
- [x] **Fix:** in-flight size grows with distance travelled.
- [x] **Fix:** fade stage draws 56×56 white flash fading by `min(life_timer*2.5, 1)`.
- [ ] **Verify:** Pulse Gun visuals match size ramp + fade flash behavior.

---

### D) Ion hit decals / effects are wrong

- [x] **Fixed:** ion hits no longer enqueue the blue `fx_queue` ground decal (`ION_TYPES` are skipped in `_queue_projectile_decals()`).
- [x] **Where:** `src/crimson/game_world.py` and `src/crimson/projectiles.py`.
- [x] **Original behavior (decompile):** ion hit spawns EffectPool-style ring + burst cloud (not floor decals):
  - `FUN_0042f270(pos, ring_scale, ring_strength)` → ring burst (`effect_id=1`)
  - `FUN_0042f540(pos, burst_scale)` → burst cloud (`effect_id=0`)
- [x] **Original per-weapon params (decompile):**
  - Ion Minigun: `FUN_0042f270(pos, 1.5, 0.1)` + `FUN_0042f540(pos, 0.8)`
  - Ion Rifle: `FUN_0042f270(pos, 1.2, 0.4)` + `FUN_0042f540(pos, 1.2)`
  - Ion Cannon: `FUN_0042f270(pos, 1.0, 1.0)` + `FUN_0042f540(pos, 2.2)`
- [x] **Fix:** remove `BEAM_TYPES` branch from `_queue_projectile_decals()`.
- [x] **Fix:** implement ion-hit ring/burst effects using EffectPool equivalents (matching params per weapon).
- [x] **Verify:** ion hits spawn ring/burst effects and no incorrect ground decal.

---

### E) Ion cannon projectile size is wrong

- [x] **Confirmed mismatch:** ion cannon beam flare is far too small.
- [x] **Original behavior (decompile):** impact/fade stage scale constants:
  - Ion Minigun → `1.05`
  - Ion Rifle → `2.2`
  - Ion Cannon → `3.5`
  - uses `size = scale * 32` (ion cannon flare ~112px wide)
- [x] **Fix:** apply the decompile scale constants for the relevant render stage (`BEAM_TYPES` render fade stage).
- [ ] **Verify:** ion cannon flare size matches the original scale relationship.

---

## 2) Fire Bullets vs weapon clip (“works wrong with some weapons”)

- [x] **Fixed:** Fire Bullets shots do **not** consume ammo:
  ```py
  if (not is_fire_bullets) and state.bonuses.reflex_boost <= 0.0:
      player.ammo = max(0.0, player.ammo - ammo_cost)
  ```
- [x] **Fixed:** Fire Bullets can still fire when `ammo == 0` (reload begins after the shot, not before).
- [x] **Fixed:** spread heat increment always uses Fire Bullets spread heat regardless of pellet count.
- [ ] **Verify:** Fire Bullets behavior is not tied to clip state; spread/accuracy feels like original.

---

## 3) Player default speed (“feels faster”)

- [x] **Fixed:** movement uses the decompile-style `move_speed` accel/decel:
  - `move_speed` ramps up while moving, decays when idle (coasts to a stop).
  - speed uses the original structure: `speed = move_speed * speed_multiplier * 25.0`.
- [x] **Original behavior (decompile):** velocity magnitude:
  - `speed = move_speed * speed_multiplier * 25.0`
  - `move_speed` accelerates up to **2.0** normally; **2.8** with Long Distance Runner perk
  - heavy weapon (Mean Minigun) clamps `move_speed` to **0.8**
  - baseline max (with `speed_multiplier=2.0`): normal `100`, runner `140`, mean minigun clamp `40`
- [x] **Fix:** replace `120.0` base constant with `25.0`.
- [x] **Fix (fidelity):** port `move_speed` accel/decel + caps/clamps (runner perk, Mean Minigun clamp).
- [ ] **Verify:** baseline speed matches original (normal/runner/minigun clamp).

---

## 4) Additional weapon parity findings

### Plasma Shotgun ammo consumption

- [x] **Verified:** consumes `1` ammo per shot (does not dump clip), while firing 14 plasma-minigun pellets.
- [x] **Verify:** clip decreases by 1 per shot; pellet behavior remains unchanged.

---

## 5) “Check all other weapons logic”

- [x] **High-level firing logic scan:** most special-case firing patterns match the decompile set (Multi‑Plasma, rocket family uses secondary pool, Gauss Shotgun, Ion Shotgun, Bubblegun).
- [x] **Known remaining gap within firing logic:** none found yet (Plasma Shotgun ammo cost verified).
- [x] **Likely biggest remaining parity gaps:** render/effects parity (secondary explosion flare rendering, ion/fire-bullets render special cases, and remaining visual verification items).
- [ ] **Deep scan:** verify `projectile_update` behavior for every weapon type (beyond ion/pulse/rocket/flame/fire‑bullets).
- [ ] **Optional deliverable:** weapon-by-weapon parity table (weapon id → expected → current → mismatch notes).

---

## 6) Recommended fix order (fastest “feels like original”)

- [x] Player speed constant (`120 → 25`) + Mean Minigun clamp
- [x] Flame angle (`dir_angle → aim_heading - pi/2`) + flame `style_id` overrides
- [x] Pulse Gun render (tint + distance-based scale + fade flash)
- [x] Ion hit effects (ring/burst) + remove incorrect `fx_queue` decal
- [x] Ion cannon flare size (scale constants)
- [x] Secondary projectile render (rocket sprite + rotation; glow/trails)
