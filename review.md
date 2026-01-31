# Weapon parity review (progress checklist)

## Status / workflow

- [x] Compared `src/` against the authoritative decompile in `analysis/` (focus: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`).
- [x] Recorded confirmed mismatches + root causes (this doc).
- [ ] Implement fixes in `src/`.
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
- [x] **Also confirmed mismatch:** Blow Torch / HR Flamer never override particle `style_id` (so they look like Flamethrower).
- [ ] **Fix:** flame particle `angle = player.aim_heading - pi/2` (not `dir_angle`).
- [ ] **Fix:** Blow Torch sets particle `style_id = 1` after spawn.
- [ ] **Fix:** HR Flamer sets particle `style_id = 2` after spawn.
- [ ] **Verify:** particles always fire forward along aim; Blow Torch/HR Flamer styles are visually distinct.

---

### B) Rocket weapons: “stubs in arsenal view”

- [x] **Confirmed mismatch:** secondary projectiles render as circles.
- [x] **Where:** `src/crimson/render/world_renderer.py` → `_draw_secondary_projectile_pool(...)`.
- [x] **Current behavior:** uses `rl.draw_circle(...)` only.
- [x] **Original behavior (decompile):** textured/rotated rocket quad using atlas frame `(grid=4, frame=3)`; rotation + glow + trail/detail effects.
- [ ] **Fix:** render secondary projectiles using atlas sprite `(grid=4, frame=3)` with rotation by heading.
- [ ] **Fix (fidelity):** add glow quad.
- [ ] **Fix (fidelity):** add trail/detail sprite effects.
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
- [ ] **Fix:** tint to green `(0.1, 0.6, 0.2, alpha*0.7)`.
- [ ] **Fix:** in-flight size grows with distance travelled.
- [ ] **Fix:** fade stage draws 56×56 white flash fading by `min(life_timer*2.5, 1)`.
- [ ] **Verify:** Pulse Gun visuals match size ramp + fade flash behavior.

---

### D) Ion hit decals / effects are wrong

- [x] **Confirmed mismatch:** we add a blue `fx_queue` floor decal for all `BEAM_TYPES`.
- [x] **Where:** `src/crimson/game_world.py` → `_queue_projectile_decals()`.
- [x] **Current behavior:**
  ```py
  elif projectile.type_id in BEAM_TYPES:
      self.fx_queue.add(effect_id=0x01, color=(0.7,0.9,1.0,1.0))
  ```
- [x] **Original behavior (decompile):** ion hit spawns EffectPool-style ring + burst cloud (not floor decals):
  - `FUN_0042f270(pos, ring_scale, ring_strength)` → ring burst (`effect_id=1`)
  - `FUN_0042f540(pos, burst_scale)` → burst cloud (`effect_id=0`)
- [x] **Original per-weapon params (decompile):**
  - Ion Minigun: `FUN_0042f270(pos, 1.5, 0.1)` + `FUN_0042f540(pos, 0.8)`
  - Ion Rifle: `FUN_0042f270(pos, 1.2, 0.4)` + `FUN_0042f540(pos, 1.2)`
  - Ion Cannon: `FUN_0042f270(pos, 1.0, 1.0)` + `FUN_0042f540(pos, 2.2)`
- [ ] **Fix:** remove `BEAM_TYPES` branch from `_queue_projectile_decals()`.
- [ ] **Fix:** implement ion-hit ring/burst effects using EffectPool equivalents (matching params per weapon).
- [ ] **Verify:** ion hits show ring/burst effects and no incorrect ground decal.

---

### E) Ion cannon projectile size is wrong

- [x] **Confirmed mismatch:** ion cannon beam flare is far too small.
- [x] **Original behavior (decompile):** impact/fade stage scale constants:
  - Ion Minigun → `1.05`
  - Ion Rifle → `2.2`
  - Ion Cannon → `3.5`
  - uses `size = scale * 32` (ion cannon flare ~112px wide)
- [ ] **Fix:** apply the decompile scale constants for the relevant render stage.
- [ ] **Verify:** ion cannon flare size matches the original scale relationship.

---

## 2) Fire Bullets vs weapon clip (“works wrong with some weapons”)

- [x] **Parity confirmed:** we do NOT subtract ammo while Fire Bullets is active:
  ```py
  if player.fire_bullets_timer <= 0.0:
      player.ammo -= ammo_cost
  ```
- [x] **Confirmed mismatch:** we still block firing if `ammo == 0` (even when Fire Bullets is active) because we early-return into reload:
  ```py
  if player.ammo <= 0.0 and not firing_during_reload:
      player_start_reload(...)
      return
  ```
- [x] **Confirmed mismatch:** spread heat increment is wrong for multi-pellet weapons (should always use Fire Bullets spread heat).
- [ ] **Fix:** allow firing during Fire Bullets even if `ammo == 0` (avoid early reload return in that case).
- [ ] **Fix:** spread heat increment always uses Fire Bullets spread heat regardless of pellet count.
- [ ] **Verify:** Fire Bullets behavior is not tied to clip state; spread/accuracy feels like original.

---

## 3) Player default speed (“feels faster”)

- [x] **Confirmed mismatch:** current movement is:
  ```py
  speed = 120.0 * speed_multiplier
  ```
  Default `PlayerState.move_speed_multiplier = 2.0`, so baseline is ~240 units/s.
- [x] **Original behavior (decompile):** velocity magnitude:
  - `speed = move_speed * speed_multiplier * 25.0`
  - `move_speed` accelerates up to **2.0** normally; **2.8** with Long Distance Runner perk
  - heavy weapon (Mean Minigun) clamps `move_speed` to **0.8**
  - baseline max: normal `50`, runner `70`, mean minigun clamp `20`
- [ ] **Fix:** replace `120.0` base constant with `25.0`.
- [ ] **Fix (fidelity):** port `move_speed` accel/decel + caps/clamps (runner perk, Mean Minigun clamp).
- [ ] **Verify:** baseline speed matches original (normal/runner/minigun clamp).

---

## 4) Additional weapon parity findings

### Plasma Shotgun ammo consumption is wrong

- [x] **Confirmed mismatch:** Plasma Shotgun drains the entire clip:
  ```py
  ammo_cost = player.ammo
  player.ammo = 0.0
  ```
- [x] **Original behavior (decompile):** consumes `1` ammo per shot (does not dump clip), while firing 14 plasma-minigun pellets.
- [ ] **Fix:** Plasma Shotgun consumes `1` ammo per shot (not the entire clip).
- [ ] **Verify:** clip decreases by 1 per shot; pellet behavior remains unchanged.

---

## 5) “Check all other weapons logic”

- [x] **High-level firing logic scan:** most special-case firing patterns match the decompile set (Multi‑Plasma, rocket family uses secondary pool, Gauss Shotgun, Ion Shotgun, Bubblegun).
- [x] **Known remaining gap within firing logic:** Plasma Shotgun ammo cost (tracked above).
- [x] **Likely biggest remaining parity gaps:** render/effects parity (rocket trails + glow, secondary explosion flare rendering, ion hit ring/burst, pulse scaling, ion/fire-bullets render special cases).
- [ ] **Deep scan:** verify `projectile_update` behavior for every weapon type (beyond ion/pulse/rocket/flame/fire‑bullets).
- [ ] **Optional deliverable:** weapon-by-weapon parity table (weapon id → expected → current → mismatch notes).

---

## 6) Recommended fix order (fastest “feels like original”)

- [ ] Player speed constant (`120 → 25`) + Mean Minigun clamp
- [ ] Flame angle (`dir_angle → aim_heading - pi/2`) + flame `style_id` overrides
- [ ] Pulse Gun render (tint + distance-based scale + fade flash)
- [ ] Ion hit effects (ring/burst) + remove incorrect `fx_queue` decal
- [ ] Ion cannon flare size (scale constants)
- [ ] Secondary projectile render (rocket sprite + rotation; optionally glow/trails)

---

If you’d like, I can draft a patch diff for the core gameplay fixes (flame angle + plasma shotgun ammo + fire bullets gating + movement constant) and separately a renderer patch (secondary projectile sprites + pulse/ion render).
