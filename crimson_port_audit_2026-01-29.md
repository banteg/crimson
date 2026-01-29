# Crimson port audit (src/ vs analysis/ decompiles)

Date: 2026-01-29

This is a focused fidelity audit comparing the current Python port in `src/` against the IDA/Ghidra decompiles in `analysis/`.
I concentrated on “already-ported” gameplay logic + the rendering pipeline, and looked for **behavioral mismatches** (not just missing features).

> **Legend**
> - **SRC** references: `src/...` with approximate line ranges (based on `nl -ba`).
> - **DECOMP** references: `analysis/ida/raw/crimsonland.exe/crimsonland.exe_decompiled.c` with line ranges and original address tags in comments.

---

## Checklist

- [x] 1) Reflex Boost slow‑motion (time scale) dt/dt_ms scaling
- [x] 2) Simulation update order (perks → effects → creatures → projectiles → players)
- [x] 3) `bonus_apply` stacking + Bonus Economist multiplier + Shock Chain semantics
- [x] 4) `bonus_pick_random_type` distribution / reroll behavior
- [x] 5) `weapon_assign_player` applies clip-size perks on weapon changes
- [x] 6) World draw order layering (dead players / effects / bonuses)
- [ ] 7) Alpha test behavior (global 4/255 cutoff) vs port shaders
- [ ] 8) Terrain render-target failure fallback path
- [ ] 9) ParticlePool + SpriteEffectPool integration/rendering

## Highest-impact fidelity mismatches

### 1) Reflex Boost slow‑motion (time scale) not implemented

**DECOMP evidence**: `gameplay_update_and_render @ 0x0040AAB0` scales `frame_dt` and `frame_dt_ms` whenever `time_scale_active` is set (driven by `bonus_reflex_boost_timer`).  
See ~L6815–L6837 in `crimsonland.exe_decompiled.c`.

Behavior:
- `time_scale_factor` is set to **0.3** while Reflex Boost is “fully active”, then ramps back to 1.0 near the end.
- `frame_dt` is multiplied by `time_scale_factor`, and **that scaled dt** is what the sim uses.

**SRC status**:
- Reflex Boost timer exists (`state.bonuses.reflex_boost`) and is decremented, but there’s no equivalent `time_scale_factor` calculation and **no dt scaling** before simulation.

Impact:
- Reflex Boost has *no slow-motion effect*.
- Any code that should “slow down with the world” (camera shake pacing, creature speed, projectile speed, bonus timers, etc.) diverges.

Suggested fix:
- Implement the DECOMP time-scale block in the gameplay step **before** calling `world_state.step()`.
- Derive `dt_ms` from the scaled dt (matching `_ftol(frame_dt*1000)` semantics).

---

### 2) Simulation update order does not match the original

**DECOMP evidence**: In `gameplay_update_and_render @ 0x0040AAB0` the update order is:
1. `perks_update_effects()`
2. `effects_update()`
3. `creature_update_all()`
4. `projectile_update()`
5. `player_update()` (per-player)

See ~L6901–L7025 in `crimsonland.exe_decompiled.c`.

**SRC status**: `src/crimson/sim/world_state.py` `WorldState.step()` currently runs:
1. effects update
2. **projectiles update**
3. **secondary projectiles update**
4. **players update**
5. creatures update
6. bonus update
7. survival progression update

See `src/crimson/sim/world_state.py` ~L79–L122.

Impact:
- Creature AI runs *after* players in your port (but *before* players in the original).
- Creature-spawned projectiles will be spawned **after** the projectile update (in your port), which adds a frame of latency vs the original (where creature projectiles can be updated immediately in the same frame’s `projectile_update()`).
- Any behavior depending on “player position from previous frame” vs “updated this frame” will differ (tracking, melee contact timing, etc.).

Suggested fix:
- Reorder your `step()` to match the original:  
  `perks_update_effects` → `effects_update` → `creatures` → `projectiles` (+ secondary) → `players` → mode updates → `bonus_update`.

---

### 3) `bonus_apply` timer stacking and side-effects are wrong / incomplete

**DECOMP evidence**: `bonus_apply @ 0x00409890` generally **adds** to timers (`timer = timer + amount*economistMultiplier`), and triggers “start” side effects only when the timer transitions from 0 → >0 (via `sub_41A810`).  
It also applies the **Bonus Economist** perk multiplier `v36 = 1.0 + 0.5*perkCount`.  
See ~L6200–L6380 in `crimsonland.exe_decompiled.c`.

**SRC issues**: `src/crimson/gameplay.py` `bonus_apply()` (~L1320+):
- Uses `max(timer, amount)` for global timers and per-player timers. That is **not** how the original stacks.
- Doesn’t apply the Bonus Economist multiplier at all.
- Doesn’t perform critical “apply-time” side effects:
  - Weapon Power Up / Reflex Boost reset ammo + cancel reload
  - Various SFX triggers (e.g., shock chain hit, etc.)
  - `sub_41A810(...)` HUD/effect kick-off gating on “timer was <= 0”
- **Shock Chain** spawns projectile type **0x14**, but DECOMP uses **21 decimal (0x15)**.
  - DECOMP: `projectile_spawn(..., 21, ownerId)` in shock chain case (bonus id 7).
  - SRC: `type_id=0x14` (~L1355–L1362).

Also: DECOMP chooses `owner_id = -100` when friendly fire is disabled; SRC always uses `-1 - player.index`.

Suggested fix:
- Replace `max(...)` with additive behavior matching DECOMP:
  - `timer += amount * (1.0 + 0.5*economistCount)`
  - preserve “start-effect” gating: only when old_timer <= 0.0
- Correct Shock Chain projectile type to 0x15 and mirror owner_id semantics.

---

### 4) `bonus_pick_random_type` distribution differs from the original

**DECOMP evidence**: `bonus_pick_random_type @ 0x00412470`:
- roll = `rand()%162 + 1`
- Points: roll 1..13
- Energizer: roll 14, but only accepted with `(rand() & 0x3F) == 0` else it becomes Weapon
- Other bonuses are mapped in a 10-step bucket loop, but if the bucket index would exceed id 14 (`++v6 >= 15`), it jumps to the validation label **without setting `v3`**, which results in a reroll (because bonus 0 fails validation).  
See ~L12088–L12130.

**SRC issue**: `src/crimson/gameplay.py` `_bonus_id_from_roll()` (~L831–L856) uses:
```py
bucket_index = (r - 13) % 120
return BonusId(WEAPON + (bucket_index // 10))
```
That **wraps** the out-of-range buckets instead of producing a reroll.

Impact:
- Bonus drop distribution differs (extra weight on early ids vs original reroll behavior).
- If you aim for bit-identical RNG consumption, this is a determinism breaker.

Also missing:
- DECOMP has extensive quest-mode restrictions and conditions (quest_stage/rank/hardcore). SRC does not implement those restrictions.

Suggested fix:
- Implement the DECOMP bucket loop literally (return 0/None to force reroll when v6 would reach 15).
- Add quest-mode gating once quest progression is implemented.

---

### 5) `weapon_assign_player` ignores clip-size perks (persistent perk effects)

**DECOMP evidence**: `weapon_assign_player @ 0x004220B0`:
- sets `player_clip_size = weapon_clip_size[weapon_id]`
- if perk Ammo Maniac: `clip += max(1, int(clip*0.25))`
- if perk My Favourite Weapon: `clip += 2`
See ~L60088–L60110 in `crimsonland.exe_decompiled.c`.

**SRC status**: `src/crimson/gameplay.py` `weapon_assign_player()` (~L861–L884):
- assigns `player.clip_size = weapon.clip_size` (base value)
- does **not** re-apply these perk-based clip adjustments on weapon changes.

Impact:
- “My Favourite Weapon” and “Ammo Maniac” won’t persist across weapon swaps (they only affect current state if you manually mutate `player.clip_size` elsewhere).
- Ammo/reload behavior diverges heavily if those perks are in play.

Suggested fix:
- In `weapon_assign_player`, compute clip size from base weapon meta + perk counts every time.

---

## Rendering pipeline mismatches

### 6) World draw order differs from original layering

**DECOMP evidence**: `gameplay_render_world @ 0x00405960` order:
1. `fx_queue_render()`
2. `terrain_render()`
3. player render (dead players)
4. `creature_render_all()`
5. player render (alive players)
6. `projectile_render()` (also renders various effect pools)
7. `bonus_render()`
8. `screen_fade_render()`  
See ~L3551–L3678 in `crimsonland.exe_decompiled.c`.

**SRC status**: `src/crimson/render/world_renderer.py` `WorldRenderer.draw()`:
- terrain/ground
- creatures
- players (all)
- projectiles
- secondary projectiles
- bonus pickups
- effect pool
- aim indicators, labels, etc.

See ~L832–L911.

Concrete mismatches:
- **Dead players** are drawn after creatures in SRC, but under creatures in DECOMP.
- `effects_render()` is part of `projectile_render()` in DECOMP and happens **before** `bonus_render()`. SRC draws effects **after** bonuses.

Suggested fix:
- Split player draw into two passes: dead then alive, matching DECOMP.
- Move effect rendering into projectile phase (before bonus pickups).

---

### 7) Alpha test is global in Grim2D; the port only emulates it for terrain stamping

**DECOMP evidence**: `grim.dll` init sets:
- `D3DRS_ALPHATESTENABLE = TRUE`
- `D3DRS_ALPHAFUNC = GREATER`
- `D3DRS_ALPHAREF = 4`
See `analysis/ghidra/raw/grim.dll_decompiled.c` ~L1535–L1551.

**SRC status**:
- Alpha-test emulation is implemented via an optional shader in `grim/terrain_render.py`, but it’s only used for terrain target stamping / specific paths.
- Most sprite rendering (players, creatures, projectiles, effects) is drawn without alpha test.

Impact:
- Sprites may show semi-transparent edge pixels that the original would discard.
- This is subtle but visible in high-contrast sprites.

Suggested fix:
- Consider an “alpha-test shader mode” wrapper for all sprite draws (or at least for assets known to rely on the 4/255 cutoff).

---

### 8) Missing fallback path when terrain render target fails

**DECOMP evidence**: Both `fx_queue_render()` and `terrain_render()` have a `terrain_texture_failed` path that draws directly to screen instead of into a texture.

**SRC status**:
- `GroundRenderer` assumes render-target usage; there isn’t a faithful “texture_failed” fallback path.

Impact:
- Port behavior diverges on platforms where render targets fail or are disabled.

---

### 9) ParticlePool and SpriteEffectPool are not integrated/rendered

**DECOMP evidence**: `projectile_render()` renders:
- projectile sprites
- particle pool (count ~0x80)
- secondary projectiles
- sprite_effect_pool (count ~0x180)
- then calls `effects_render()`
See around where `effects_render()` is called (~L33260+).

**SRC status**:
- Only the “EffectPool” is rendered (`_draw_effect_pool`).
- No ParticlePool / SpriteEffectPool in `GameplayState` or renderer.

Impact:
- Significant missing visuals (sparks, dust, transient sprite effects).

---

## Notes: places that look good / already match

- Camera clamp to `[-1, screen_w - terrain_w]` and shake pulse logic match the decompile well.
- Terrain generation RNG consumption order (rotation → Y → X) matches the decompile (and contradicts one note in `docs/terrain.md`).

---

## Quick punch list (action order)

1. Implement Reflex Boost time scaling (dt + dt_ms scaling).
2. Fix sim update ordering (creatures before projectile_update, etc).
3. Fix `bonus_apply` stacking + shock chain projectile type.
4. Fix bonus random distribution (`_bonus_id_from_roll` reroll behavior).
5. Fix weapon assignment to reapply clip-size perks on weapon change.
6. Adjust world rendering order (dead players under creatures, effects under bonuses).
7. Decide whether to apply alpha-test globally for faithful sprite edges.
8. Integrate missing particle/sprite effect pools once gameplay is ready.
