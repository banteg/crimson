Below is a **parity audit for Perk IDs 0–20**, comparing:

* ✅ **Original behavior** (from **authoritative decompile**: `analysis/ghidra/raw/crimsonland.exe_decompiled.c`, plus docs)
* ✅ **Our port behavior** (from `src/`)
* ⚠️ **Parity gaps** I found (with suggested fix locations)

I’ve structured this so you can drop it into a doc as-is.

---

# ✅ Summary (IDs 0–20)

| ID | Perk                        | Original behavior present in port? | Notes / Gaps                                                            |
| -: | --------------------------- | ---------------------------------- | ----------------------------------------------------------------------- |
|  0 | AntiPerk                    | ✅                                  | Sentinel / not offered                                                  |
|  1 | Bloody Mess / Quick Learner | ✅                                  | Mostly visuals; see note re FX toggle & extra decals                    |
|  2 | Sharpshooter                | ✅                                  | Laser + spread/rof changes                                              |
|  3 | Fastloader                  | ✅                                  | Reload time *0.7                                                        |
|  4 | Lean Mean Exp. Machine      | ✅                                  | Timer-based XP drip                                                     |
|  5 | Long Distance Runner        | ✅                                  | Speed ramp to 2.8                                                       |
|  6 | Pyrokinetic                 | ✅                                  | Correct timing + particle intensities                                   |
|  7 | Instant Winner              | ✅                                  | +2500 XP                                                                |
|  8 | Grim Deal                   | ✅                                  | +18% XP then death                                                      |
|  9 | Alternate Weapon            | ✅                                  | Weapon-slot swap + speed penalty                                        |
| 10 | Plaguebearer                | ⚠️ **GAP**                         | Per-player flag sync problem (multiplayer parity)                       |
| 11 | Evil Eyes                   | ✅                                  | Freezes target near aim                                                 |
| 12 | Ammo Maniac                 | ✅                                  | Clip size +25% + weapon reassignment                                    |
| 13 | Radioactive                 | ✅                                  | Correct timer reset + falloff dmg                                       |
| 14 | Fastshot                    | ✅                                  | Shot cooldown *0.88                                                     |
| 15 | Fatal Lottery               | ✅                                  | rand&1 → +10000 XP or death                                             |
| 16 | Random Weapon               | ✅                                  | Quest-only random weapon assignment                                     |
| 17 | Mr. Melee                   | ⚠️ **GAP**                         | We suppress player damage if MR_MELEE kills attacker; original does not |
| 18 | Anxious Loader              | ✅                                  | -0.05 reload per click while reloading                                  |
| 19 | Final Revenge               | ✅                                  | 512 range, falloff dmg, bonus guard                                     |
| 20 | Telekinetic                 | ✅                                  | Aim-hover pickup after 650ms                                            |

---

# Perk-by-perk documentation (Original vs Port)

For each perk: **what it does in original** + **where it lives in our port** + **gaps**.

---

## 0 — AntiPerk

### Original

* Exists as a sentinel (“no perk” / placeholder) and is **not offered**.
* Used in tables and unlock metadata.

### Port

* `src/crimson/gameplay.py`: `perk_can_offer()` rejects id 0.

### Gaps

* None.

---

## 1 — Bloody Mess / Quick Learner (same ID, name depends on FX toggle)

### Original

* **XP multiplier on kills**: `xp_base = int(reward_value * 1.3)` if perk present.
* **Extra gore FX on projectile hit**:

  * adds extra random decals (calls to `fx_queue_add_random`)
  * spawns blood splatter particles (suppressed if FX toggle disables blood)
* **Name/description swap** based on config:

  * If blood enabled: “Bloody Mess”
  * If disabled: “Quick Learner”

### Port

* XP multiplier:

  * `src/crimson/creatures/runtime.py`: XP award path uses perk count multiplier
* Hit FX:

  * `src/crimson/game_world.py:_queue_projectile_decals()`
  * blood particles suppressed via `fx_toggle`
* UI name/description:

  * `src/crimson/perks.py:perk_display_name()` / `perk_display_description()`

### ⚠️ Potential parity note (not confirmed)

If original suppressed *all* extra gore-related decals when FX disabled, we may still be spawning extra **non-particle decals** (depends what `fx_queue_add_random` maps to in assets). Worth verifying once assets are stable.

---

## 2 — Sharpshooter

### Original

* `player_fire_weapon`:

  * shot cooldown *= **1.05**
  * spread_heat set to **0.02**
* Renderer draws **laser sight line**.

### Port

* Combat logic:

  * `src/crimson/gameplay.py:player_fire_weapon()`
  * `src/crimson/gameplay.py:player_update()` keeps spread_heat pinned at 0.02
* Rendering:

  * `src/crimson/render/world_renderer.py:_draw_sharpshooter_laser_sight()`

### Gaps

* None found.

---

## 3 — Fastloader

### Original

* Reload time *= **0.7**

### Port

* `src/crimson/gameplay.py:player_start_reload()`

### Gaps

* None.

---

## 4 — Lean Mean Exp. Machine

### Original

* Every **0.25s**, adds: `perk_count * 10 XP`

### Port

* `src/crimson/gameplay.py:perks_update_effects()`
* Uses `state.lean_mean_exp_timer` and resets to 0.25.

### Gaps

* None.

---

## 5 — Long Distance Runner

### Original

* When moving:

  * speed ramps to 2.0 normally
  * with perk, continues to **2.8** (+dt each frame beyond 2.0)
* When not moving:

  * speed decays by **dt*15**

### Port

* `src/crimson/gameplay.py:player_update()` implements ramp/decay.

### Gaps

* None.

---

## 6 — Pyrokinetic

### Original (from decompile)

* In `perks_update_effects`:

  * Finds creature near aim (radius 12)
  * decrements target’s `collision_timer` by dt
  * when <0: sets `collision_timer = 0.5`, emits 5 particles intensities:

    * **0.8, 0.6, 0.4, 0.3, 0.2**
  * also calls `fx_queue_add_random`

### Port

* `src/crimson/gameplay.py:perks_update_effects()`

### Gaps

* None (matches decompile precisely).

---

## 7 — Instant Winner

### Original

* On apply: `experience += 2500`
* Stackable.

### Port

* `src/crimson/gameplay.py:perk_apply()`

### Gaps

* None.

---

## 8 — Grim Deal

### Original

* On apply:

  * `experience += int(experience * 0.18)`
  * `health = -1.0`

### Port

* `src/crimson/gameplay.py:perk_apply()`

### Gaps

* None.

---

## 9 — Alternate Weapon

### Original

* Quest-only perk.
* Adds alternate weapon slot
* Movement speed *= **0.8**
* Reload key swaps weapons:

  * swaps runtime weapon state blocks
  * plays reload SFX
  * adds **+0.1** shot cooldown when swapping

### Port

* Swap + carry:

  * `src/crimson/gameplay.py:bonus_apply()` handles pick-up behavior
  * `src/crimson/gameplay.py:player_swap_alt_weapon()`
* Speed penalty + swap trigger:

  * `src/crimson/gameplay.py:player_update()`

### Gaps

* None found.

---

## 10 — Plaguebearer

### Original

* On apply: sets `player_plaguebearer_active = 1`
* Effects in creature update:

  * Player infects nearby creatures:

    * if creature HP <150 and infection_count <50 and dist <30
  * Infected creatures:

    * take 15 dmg every 0.5s (uses collision_timer add-wrap)
    * if die: infection_count++ and handled as normal death
  * Infection spreads between creatures within 45 units if infection_count <60

### Port

* Flag set:

  * `src/crimson/gameplay.py:perk_apply()` sets `owner.plaguebearer_active = True`
* Creature-side mechanics:

  * `src/crimson/creatures/runtime.py` infection tick + spread logic

### ⚠️ PARITY GAP (multiplayer)

We only set **plaguebearer_active on the perk owner (player0)**, but creature infection proximity check is keyed off the current target player’s `player.plaguebearer_active`.

That diverges from original behavior, which references `player_plaguebearer_active` as a single global (player0 struct field), meaning plague effect should apply regardless of which player the creature is interacting with.

✅ **Suggested fix**
In `src/crimson/gameplay.py:perk_apply()` branch for `PerkId.PLAGUEBEARER`, set flag for all players:

```py
for p in players:
    p.plaguebearer_active = True
```

(or treat it as global by checking `players[0]` in creature logic, but syncing is cleaner and matches how we handle perk_counts.)

---

## 11 — Evil Eyes

### Original

* `perks_update_effects`:

  * sets global `evil_eyes_target_creature = creature_find_in_radius(aim, 12)`
  * else -1
* `creature_update_all`:

  * if creature index == target, **skip AI update** (movement stays frozen)

### Port

* Target set:

  * `src/crimson/gameplay.py:perks_update_effects()`
* Freeze logic:

  * `src/crimson/creatures/runtime.py` sets move_scale=0, vel=0 when index matches target

### Gaps

* None.

---

## 12 — Ammo Maniac

### Original

* Increases clip size by:

  * `clip += max(1, int(clip * 0.25))`
* On pick: reassign current weapon for each player so clip recalculates

### Port

* Clip size calc:

  * `src/crimson/gameplay.py:weapon_assign_player()`
* On pick:

  * `src/crimson/gameplay.py:perk_apply()` loops players and calls weapon_assign_player

### Gaps

* None.

---

## 13 — Radioactive

### Original (from decompile)

* For creatures within 100 units:

  * `collision_timer -= dt*1.5`
  * if <0: `collision_timer = 0.5`
  * HP -= `(100 - dist) * 0.3`
  * spawns random FX
* If kill:

  * if type_id==1: hp=1 (immune)
  * else: award XP and “soft kill” by shrinking hitbox (skip normal death handler)

### Port

* `src/crimson/creatures/runtime.py` radioactive block matches the decompile:

  * assignment reset to 0.5 (✅)
  * falloff damage (✅)
  * soft death (✅)

### Gaps

* None.

---

## 14 — Fastshot

### Original

* shot_cooldown *= 0.88

### Port

* `src/crimson/gameplay.py:player_fire_weapon()`

### Gaps

* None.

---

## 15 — Fatal Lottery

### Original

* Stackable.
* `rand() & 1`:

  * 0 → XP += 10000
  * 1 → health = -1

### Port

* `src/crimson/gameplay.py:perk_apply()` uses `state.rng.rand()` & 1

### Gaps

* None.

---

## 16 — Random Weapon

### Original

* Quest-only, stackable.
* Picks random available weapon (retry ~100), skipping pistol and current.
* Calls weapon_assign.

### Port

* `src/crimson/gameplay.py:perk_apply()` via `weapon_pick_random_available()`

### Gaps

* None.

---

## 17 — Mr. Melee

### Original (confirmed in decompile)

* When creature lands a melee tick:

  * if perk active: `creature_apply_damage(creature, 25, type=2, impulse=0)`
  * **then player damage still proceeds**
* Importantly, original **does not branch on whether that damage killed the creature**.

### Port

* Implemented in `src/crimson/creatures/runtime.py` within contact tick
* But if MR_MELEE kills creature, we:

  * handle death immediately
  * **`continue`**, skipping player_take_damage for that tick

### ⚠️ PARITY GAP (definite)

In original, player still takes the contact damage even if MR_MELEE kills attacker; our early `continue` prevents that.

✅ **Suggested fix**
In `src/crimson/creatures/runtime.py`, inside the MR_MELEE block:

* remove the `continue`
* defer death handling until after player damage (or mark pending and process later)

This is the exact mismatch visible in the decompile snippet around the MR_MELEE branch (lines near the `perk_id_mr_melee` reference in the radioactive/contact damage region).

---

## 18 — Anxious Loader

### Original

* While reloading:

  * each primary-fire press reduces reload_timer by 0.05
  * if it would go <=0, sets it to `dt*0.8` to ensure completion logic triggers

### Port

* `src/crimson/gameplay.py:player_update()`
* We clamp at 0 instead of `dt*0.8`, but completion logic still triggers correctly in our loop ordering.

### Gaps

* Likely none; behavior equivalent in practice. (If you want perfect float-state parity, we could replicate the `dt*0.8` writeback.)

---

## 19 — Final Revenge

### Original

* When player dies (health crosses below 0):

  * sets `bonus_spawn_guard`
  * spawns explosion burst (scale ~1.8)
  * applies radial damage within 512:

    * `damage = (512 - dist) * 5.0`
  * plays `sfx_explosion_large` + `sfx_shockwave`
  * resets guard

### Port

* `src/crimson/sim/world_state.py` matches:

  * range 512
  * falloff formula
  * guard toggle
  * SFX events

### Gaps

* None.

---

## 20 — Telekinetic

### Original

* Aim-hover bonus within radius 24
* If hover persists >650ms, auto-pickup

### Port

* `src/crimson/gameplay.py:bonus_telekinetic_update()`
* Uses `bonus_find_aim_hover_entry()` and per-player timers.

### Gaps

* None.

---

# ✅ Concrete parity gaps found

## GAP A — Plaguebearer active flag not synced across players

* **File:** `src/crimson/gameplay.py`
* **Function:** `perk_apply()`
* **Issue:** sets `plaguebearer_active` only on perk owner
* **Fix:** set it on all `players` (or treat as global consistently)

---

## GAP B — Mr. Melee prevents player damage if it kills attacker

* **File:** `src/crimson/creatures/runtime.py`
* **Location:** MR_MELEE contact tick block
* **Issue:** our `continue` skips player_take_damage; original does not branch
* **Fix:** remove early `continue`; defer death processing

---

# What I did *not* fully audit (but can if you want)

To stay inside your requested scope (IDs 0–20), I didn’t fully audit:

* cross-perk interactions (e.g., Bloody Mess + Double XP + Fire Bullets)
* perk unlock gating by meta progression (career XP)
* UI icon/atlas parity for perk display

If you want, I can do a second pass focused on **cross-perk interactions** for these IDs (that’s where subtle parity bugs usually hide).

---

If you want this written directly into a `docs/perks_0_20_parity.md` format (ready to commit), say so and I’ll output it in that style.

Below is a **perk-by-perk parity audit for perk IDs 21–40** (original Crimsonland vs our port), plus the **remaining gaps I can confirm** in this range and **where to fix them**.

---

## Parity gaps found (IDs 21–40)

### 1) Regression Bullets / Ammunition Within: **we incorrectly require `ammo <= 0` to fire during reload**

**Original:** while `reload_timer != 0`, you can still shoot (if you have XP) and pay **XP** (Regression Bullets) or **HP** (Ammunition Within). There is **no ammo==0 check**—so it also works when the player **manually reloads early** (ammo still > 0).
**Our version:** `player_fire_weapon()` blocks firing during reload unless `ammo <= 0`, so **manual early reload disables the perk effect**.

**Fix location:** `src/crimson/gameplay.py` → `player_fire_weapon()` reload block around lines ~1659–1682.

**Suggested change:** remove the `player.ammo <= 0.0` requirement; gate only on:

* `player.reload_timer > 0`
* `player.experience > 0`
* perk active (Regression Bullets or Ammunition Within)

Also update/add a test to cover “reload started with ammo > 0”.

---

### 2) Poison perks (Poison Bullets / Veins of Poison / Toxic Avenger): **missing original poison visuals + missing “damage as apply_damage” tick behavior**

These perks all ultimately set `creature.flags` poison bits and rely on the poison tick in `creature_update_all`.

**2a — Missing red poison aura render**
**Original:** poisoned creatures (`flags & 1`) get a **red 60×60 quad** drawn behind them (effect atlas id `0x12`) with corpse-fade alpha.
**Our version:** `WorldRenderer` does **not** draw any poison overlay at all.

**Fix location:** `src/crimson/render/world_renderer.py` in the creature loop where Monster Vision highlights are drawn (around the same section that draws atlas `0x10`). Add a branch for `creature.flags & CreatureFlags.SELF_DAMAGE_TICK` to draw atlas `0x12` at 60×60.

**2b — Poison tick uses “apply damage” in original (flash/jitter), but we directly subtract HP**
**Original:** poison tick calls `creature_apply_damage(creature_idx, dmg, damage_type=0, impulse=0)`. That means it also triggers **hit flash timer** and **heading jitter** that normal damage applies.
**Our version:** in `CreaturePool.update`, we directly do `creature.hp -= dmg` and only call `handle_death()` if needed. This skips the “on damage” side-effects.

**Fix location:** `src/crimson/creatures/runtime.py` around lines ~396–414 (the `SELF_DAMAGE_TICK` / `SELF_DAMAGE_TICK_STRONG` block).
**Suggested approach:** call `creature_apply_damage(...)` instead of raw subtraction, but preserve kill credit:

* pass `owner_id=creature.last_hit_owner_id` (so poison kills stay attributed the same way)

---

### 3) Doctor: **we don’t draw the target HP bar for dead “still-active” corpses**

**Original:** the Doctor bar draws as long as the “target creature” exists; the ratio is clamped so a corpse would show as **0%** (empty bar) during fade-out while it’s still targetable.
**Our version:** `_draw_target_health_bar()` bails out on `hp <= 0`, so corpses never show the bar even if still targetable by `_creature_find_in_radius`.

**Fix location:** `src/crimson/modes/base_gameplay_mode.py` → `_draw_target_health_bar()` around lines ~100–120.
**Suggested change:** remove the `hp <= 0.0` early-return; instead compute ratio with clamp (so dead → 0).

---

### 4) Hot Tempered: **owner_id ignores our `friendly_fire_enabled` toggle**

**Original:** Hot Tempered ring projectiles use:

* `owner_id = -100` if friendly fire is **off**
* `owner_id = -1 - player_index` if friendly fire is **on**

**Our version:** always uses `_owner_id_for_player(player.index)` (always `-1 - player_index`), ignoring `state.friendly_fire_enabled`.

**Fix location:** `src/crimson/gameplay.py` → `_perk_update_hot_tempered()` around lines ~321–356.
**Suggested change:** mirror what we already do for Shock Chain bonus: choose `-100` when friendly fire disabled.

---

# Perk-by-perk documentation (21–40)

For each perk below:

* **Original behavior** = what the EXE actually does (with key hooks)
* **Our implementation** = where it lives in `src/`
* **Parity notes** = gaps or “looks good”

---

## 21) PERK_EXPERT

### Original behavior

* **Perk selection UI** offers **6 choices** (instead of 5), unless Perk Master is owned (then 7).
* Also tweaks perk list layout spacing for the extra entry and shows sponsor line:

  * “extra perk sponsored by the Perk Expert”

### Our implementation

* `src/crimson/gameplay.py`: `perk_choice_count()` returns **6** when Expert active and Master not active.
* `src/crimson/ui/perk_menu.py`: expert layout constants (`MENU_LIST_STEP_EXPERT`, `MENU_LIST_Y_EXPERT`, sponsor X, etc).
* `src/crimson/views/perks.py`: sponsor text string selection.

### Parity notes

* ✅ Looks faithful for choice count + layout + sponsor line.

---

## 22) UNSTOPPABLE

### Original behavior

When the player takes damage (and the hit wasn’t dodged):

* If **Unstoppable NOT owned**:

  * player heading gets random knock: `heading += ((rand%100)-50) * 0.04`
  * `spread_heat += damage * 0.01` clamped to max `0.48`
* If **Unstoppable owned**: those two effects are skipped (damage still applies normally).

### Our implementation

* `src/crimson/player_damage.py`: `player_take_damage()` matches this gating.

### Parity notes

* ✅ Mechanics match.

---

## 23) REGRESSION_BULLETS

### Original behavior

Two key hooks:

1. **Reload-start guard**
   If already reloading and (Regression Bullets OR Ammunition Within) is active, **don’t restart reload** (prevents reload-reset abuse).

2. **Fire during reload by paying XP**
   When trying to shoot while `reload_timer != 0`:

* Allowed only if **experience > 0** and Regression Bullets (or Ammunition Within) is owned.
* If Regression Bullets is owned, cost is:

  * `exp -= reload_time * 4.0` if `weapon_ammo_class == 1`
  * `exp -= reload_time * 200.0` otherwise
    (clamp exp ≥ 0)
* Shot fires **without consuming ammo** while reloading.

⚠️ **No ammo==0 check**: it works any time you are reloading (including manual reload with ammo still in clip).

### Our implementation

* `src/crimson/gameplay.py`:

  * `player_start_reload()` has the reload-restart guard.
  * `player_fire_weapon()` implements firing during reload and the XP cost formula.

### Parity notes

* ❌ **Gap:** `player_fire_weapon()` currently requires `player.ammo <= 0.0` before allowing the “fire during reload” path. Original does not.
* ✅ XP cost math (4 vs 200 factor) looks correct.

**Fix:** `src/crimson/gameplay.py:player_fire_weapon()` reload block (~1659–1682).

---

## 24) INFERNAL_CONTRACT

### Original behavior

On pick:

* Set **every alive player’s** health to `0.1`
* Give the picking player:

  * `level += 3`
  * `perk_pending_count += 3`
    Offer restriction:
* Blocked when **Death Clock** is active.

### Our implementation

* `src/crimson/gameplay.py`: `perk_apply()` handles HP=0.1 for alive players and grants owner +3 levels/+3 perk picks.
* `src/crimson/gameplay.py`: perk-generation blocks it when Death Clock active.

### Parity notes

* ✅ Looks faithful.

---

## 25) POISON_BULLETS

### Original behavior

On projectile hit to a creature:

* If Poison Bullets owned and `(rand & 7) == 1` (1/8), set:

  * `creature.flags |= 1` (poison tick enabled)

Poison tick processing:

* Each frame in `creature_update_all`:

  * if `flags & 2`: self-damage = `dt * 180`
  * else if `flags & 1`: self-damage = `dt * 60`
  * damage applied via `creature_apply_damage(..., damage_type=0, impulse=0)`

Visual:

* In world render: if `flags & 1`, draw **red 60×60 aura** (effect atlas `0x12`) behind the creature, fading out as corpse shrinks.

### Our implementation

* Apply poison flag:

  * `src/crimson/projectiles.py`: on hit, applies `CreatureFlags.SELF_DAMAGE_TICK` with `rand & 7 == 1` when owner perk active.
* Tick damage:

  * `src/crimson/creatures/runtime.py`: applies `dt*60`/`dt*180` based on flags.

### Parity notes

* ❌ **Gap (visual):** missing red aura draw (`0x12`) in `WorldRenderer`.
* ❌ **Gap (behavioral side-effects):** poison tick is raw `hp -= dmg`; original uses `creature_apply_damage`, which also triggers hit flash + heading jitter.

**Fixes:**

* Render: `src/crimson/render/world_renderer.py` creature overlay section.
* Tick: `src/crimson/creatures/runtime.py` self-damage tick block (~396–414).

---

## 26) DODGER

### Original behavior

When taking damage (after Thick Skinned multiplier):

* If Ninja is **not** owned and Dodger is owned:

  * 1/5 chance (`rand % 5 == 0`) to **dodge** the hit (no damage applied)

### Our implementation

* `src/crimson/player_damage.py`: `player_take_damage()` checks Ninja first, then Dodger.

### Parity notes

* ✅ Mechanics match (priority under Ninja preserved).

---

## 27) BONUS_MAGNET

### Original behavior

In bonus spawn-on-kill logic:

* Base chance: `rand % 9 == 1` → spawn
* Special-case for pistol: if base roll fails, pistol has extra `rand % 5 == 1` chance to allow spawn
* If still not spawned:

  * if Bonus Magnet owned: additional chance `rand % 10 == 2` to spawn

### Our implementation

* `src/crimson/gameplay.py`: `BonusPool.try_spawn_on_kill()` matches this flow.

### Parity notes

* ✅ Looks faithful.

---

## 28) URANIUM_FILLED_BULLETS

### Original behavior

In `creature_apply_damage`:

* If `damage_type == 1` (bullet) and Uranium owned:

  * `damage *= 2.0`

### Our implementation

* `src/crimson/creatures/damage.py`: applies `* 2.0` for bullet damage when perk active.

### Parity notes

* ✅ Looks faithful.

---

## 29) DOCTOR

### Original behavior

Two effects:

1. **Bullet damage multiplier**

* In `creature_apply_damage`: if bullet damage, multiply by **1.2**

2. **Target health bar UI**

* Each frame, a “target creature under aim” is selected via `creature_find_in_radius(aim_pos, 12.0, start=0)`
* HUD draws a 64px health bar above that creature showing `health/max_health` (clamped 0..1)
* This selection logic is shared with Pyrokinetic/Evil Eyes targeting.

### Our implementation

* Damage:

  * `src/crimson/creatures/damage.py`: bullet damage *1.2.
* UI:

  * `src/crimson/modes/base_gameplay_mode.py` `_draw_target_health_bar()` uses `_creature_find_in_radius()`.
  * `src/crimson/ui/hud.py` draws the bar.

### Parity notes

* ⚠️ **Minor gap:** we return early if `hp <= 0`, so dead-but-still-active corpses won’t show a 0% bar. Original would draw an empty bar (ratio clamped to 0) as long as the corpse remains targetable.
* ✅ Otherwise matches.

**Fix:** `src/crimson/modes/base_gameplay_mode.py:_draw_target_health_bar()` (remove `hp <= 0` early-return).

---

## 30) MONSTER_VISION

### Original behavior

* **Offer restriction:** not offered if FX detail is off.
* Rendering:

  * Disables creature shadow pass when active.
  * Draws a **yellow 90×90 quad** (effect atlas `0x10`) behind every active creature (with corpse fade alpha).

### Our implementation

* Offer gating: `src/crimson/gameplay.py` perk generation checks `state.config.fx_detail`.
* Rendering:

  * `src/crimson/render/world_renderer.py` draws atlas `0x10` behind creatures when Monster Vision active.
  * Shadow pass disabled when perk active.

### Parity notes

* ✅ Looks faithful.

---

## 31) HOT_TEMPERED

### Original behavior

* Timer logic uses a global interval variable (`flt_473318`-style):

  * `player.hot_tempered_timer += dt`
  * if `global_interval < timer`: spawn, `timer -= global_interval`, then `global_interval = (rand % 8) + 2.0`
* Spawn:

  * Emit **8 projectiles** in a ring around the player at angles `i * (pi/4)`
  * Alternating projectile types:

    * even indices: Plasma Minigun bullet
    * odd indices: Plasma Rifle bullet
* Owner id:

  * `-100` if friendly fire off
  * `-1-player_index` if friendly fire on

### Our implementation

* `src/crimson/gameplay.py`: `_perk_update_hot_tempered()` matches timer/randomization and projectile ring.

### Parity notes

* ❌ **Gap:** owner_id ignores `state.friendly_fire_enabled`; we always use `-1-player_index`.

**Fix:** in `_perk_update_hot_tempered()`, choose owner id based on `state.friendly_fire_enabled`.

---

## 32) BONUS_ECONOMIST

### Original behavior

* When applying time-based bonuses, duration increment is multiplied by **1.5**.

### Our implementation

* `src/crimson/gameplay.py`: `bonus_apply()` uses `economist_multiplier = 1.0 + 0.5 * perk_count` (→ 1.5 when owned).

### Parity notes

* ✅ Equivalent in normal gameplay (perk isn’t stackable).

---

## 33) THICK_SKINNED

### Original behavior

Two effects:

1. On perk pick:

* For each alive player: `health = max(1.0, health * 2/3)`

2. On damage taken:

* Damage multiplier: `damage *= 2/3` (applied before dodge logic)

Offer restriction:

* Blocked when Death Clock is active.

### Our implementation

* `src/crimson/gameplay.py`: `perk_apply()` reduces current HP on pick.
* `src/crimson/player_damage.py`: `player_take_damage()` applies `* 2/3`.
* perk selection: blocked by Death Clock.

### Parity notes

* ✅ Looks faithful.

---

## 34) BARREL_GREASER

### Original behavior

Two effects:

1. Bullet damage boost:

* In `creature_apply_damage`, bullet damage `* 1.4`

2. Faster projectile stepping:

* In `projectile_update`, if perk active and `owner_id < 0`, movement steps are doubled.

### Our implementation

* `src/crimson/creatures/damage.py`: bullet damage `* 1.4`
* `src/crimson/projectiles.py`: doubles movement steps when perk is active and `owner_id < 0`

### Parity notes

* ✅ Looks faithful.

---

## 35) AMMUNITION_WITHIN

### Original behavior

Same “fire during reload” mechanic as Regression Bullets, but instead of XP cost it costs HP:

* Allowed while `reload_timer != 0` only if `experience > 0` and perk active.
* If Regression Bullets is also owned, Regression Bullets takes precedence (HP cost won’t happen).
* Damage cost per shot:

  * `0.15` if `weapon_ammo_class == 1`
  * else `1.0`
* Damage is applied via `player_take_damage` (so Thick Skinned, Dodger/Ninja interactions apply).

Also shares the reload-restart guard in `player_start_reload`.

### Our implementation

* `src/crimson/gameplay.py`:

  * `player_start_reload()` blocks restart when perks active.
  * `player_fire_weapon()` applies self-damage cost via `player_take_damage()`.

### Parity notes

* ❌ **Gap:** same as Regression Bullets—our code requires `ammo <= 0` to use the perk during reload; original does not.
* ✅ Cost values and precedence (Regression over Ammo Within) match.

**Fix:** `src/crimson/gameplay.py:player_fire_weapon()` reload block.

---

## 36) VEINS_OF_POISON

### Original behavior

On melee contact hit to player (only if player shield timer is 0):

* If Toxic Avenger is not active and Veins of Poison is active:

  * `creature.flags |= 1` (poison tick)

Also affected by hardcore quest offer rules:

* In Hardcore Quest levels 2–10, certain poison perks may be blocked (selection gating).

### Our implementation

* `src/crimson/creatures/runtime.py`: on contact damage, applies poison tick flag when shield is down.
* `src/crimson/gameplay.py`: perk offering rules include the hardcore poison gating.

### Parity notes

* ❌ Shares poison-system gaps:

  * missing red aura render
  * poison tick doesn’t go through `creature_apply_damage` side-effects

---

## 37) TOXIC_AVENGER

### Original behavior

On melee contact hit to player (only if shield timer is 0):

* If Toxic Avenger is active:

  * `creature.flags |= 3` (normal + strong poison tick flags)

Prereq:

* Requires Veins of Poison.

### Our implementation

* `src/crimson/creatures/runtime.py`: applies both flags.
* perk prereq enforced by perk metadata / offering.

### Parity notes

* ❌ Shares poison-system gaps (same as 25/36).

---

## 38) REGENERATION

### Original behavior

Each frame:

* If Regeneration owned and `(rand & 1) != 0`:

  * For each alive player with `0 < health < 100`: `health += dt`

### Our implementation

* `src/crimson/gameplay.py`: `perk_update_effects()` implements this.

### Parity notes

* ✅ Looks faithful.

---

## 39) PYROMANIAC

### Original behavior

* Offer gating: only offered when current weapon is Flamethrower.
* Damage:

  * In `creature_apply_damage`, if `damage_type == 4` and Pyromaniac owned:

    * `damage *= 1.5`
    * consumes a `rand()` call (side-effect only)

### Our implementation

* `src/crimson/gameplay.py`: perk generation only allows Pyromaniac with Flamethrower.
* `src/crimson/creatures/damage.py`: fire damage `* 1.5` and consumes RNG.

### Parity notes

* ✅ Looks faithful.

---

## 40) NINJA

### Original behavior

When taking damage:

* If Ninja owned: 1/3 chance (`rand % 3 == 0`) to dodge completely.
* Checked before Dodger, so it **overrides** Dodger behavior.

### Our implementation

* `src/crimson/player_damage.py`: Ninja check happens first, then Dodger.

### Parity notes

* ✅ Looks faithful.

---

# Quick “to-fix” checklist (just the actionable bits)

1. **Reload perks ammo check**

* File: `src/crimson/gameplay.py`
* Function: `player_fire_weapon()`
* Remove `ammo <= 0` requirement in reload firing path.

2. **Poison visuals**

* File: `src/crimson/render/world_renderer.py`
* Add draw for poisoned creatures (effect atlas `0x12`, 60×60, faded alpha).

3. **Poison tick should behave like damage**

* File: `src/crimson/creatures/runtime.py`
* In self-damage tick block: call `creature_apply_damage` (damage_type 0, impulse 0), preserving `last_hit_owner_id`.

4. **Doctor bar on corpses**

* File: `src/crimson/modes/base_gameplay_mode.py`
* In `_draw_target_health_bar`: don’t early-return on `hp <= 0`.

5. **Hot Tempered owner id**

* File: `src/crimson/gameplay.py`
* In `_perk_update_hot_tempered`: use `-100` when `state.friendly_fire_enabled` is false.

If you want, I can also sketch exact patch diffs for each fix in our codebase (minimal edits, plus 1–2 targeted tests to prevent regressions).

Below is a **perk-by-perk parity audit for Perk IDs 40–57** (inclusive), based on the authoritative decompile in `analysis/ghidra/raw/crimsonland.exe_decompiled.c` and our current implementation under `src/`.

I’ve split this into:

1. **Gaps summary** (what’s still wrong / missing)
2. **Perk-by-perk documentation**: “original behavior” vs “our version” + **fix suggestions** where needed

---

## Remaining parity gaps I found (40–57)

### 1) **Perk 47: Death Clock is missing the 30-second kill drain**

**Original** drains HP every frame: `health -= frame_dt * 3.3333333` (100 HP / 30s), while making you immune to all other damage.
**Our version** currently gives “immune + set HP to 100” but **never drains**, making it effectively permanent invulnerability.

✅ Suggested fix: implement the drain in `src/crimson/gameplay.py::perks_update_effects()`.

---

### 2) **Perk 54: Fire Caugh aim/spread, muzzle offset, and extra effects are simplified**

Original Fire Caugh uses the *same style* of aim jitter you already implemented for normal shooting (distance-scaled + `spread_heat`), plus a fixed muzzle angular offset and an extra spawned sprite FX + two SFX.
Our `_perk_update_fire_cough()` currently uses a small constant jitter and a simpler muzzle position and does not spawn the sprite FX / play the two SFX.

✅ Suggested fix: rewrite `src/crimson/gameplay.py::_perk_update_fire_cough()` using the same logic pattern as `player_fire_weapon()`.

---

### 3) **Perk-spawned projectiles don’t respect the original “friendly fire off” owner-id sentinel**

Original uses:

* `owner_id = -100` when friendly fire is **off** (so player projectiles don’t collide with players)
* `owner_id = -1 - player_index` when friendly fire is **on** (so they can hit the other player)

In our perk code paths (Angry Reloader / Man Bomb / Fire Caugh), we always use `-1 - player_index` via `_owner_id_for_player()`.

✅ Suggested fix: change owner-id selection for perk projectile spawns to match the original (see notes under perks 50/53/54).

---

### 4) **Perk 53: Man Bomb shouldn’t temporarily set `bonus_spawn_guard`**

In the original Man Bomb block, `bonus_spawn_guard` isn’t toggled during the spawn.
We currently wrap the spawn with `state.bonus_spawn_guard = True/False`.

This is mostly harmless today, but it becomes relevant if we later add a true “projectile_spawn parity wrapper” (Fire Bullets conversion and other side effects use this guard in the original).

✅ Suggested fix: remove the guard wrap in `_perk_update_man_bomb()`.

---

### 5) (Optional parity) Trial/full-version perk gating

Original `perk_can_offer @ 0x0042fb10` has explicit logic tied to `game_is_full_version()` and treats **Man Bomb / Fire Caugh / Living Fortress / Tough Reloader** specially.
Our port doesn’t currently have “full version gating” for perks (we do have `demo_mode_active`, but it’s used elsewhere).

✅ If you care about demo/trial fidelity: implement this in our perk offering logic.

---

# Perk-by-perk documentation (IDs 40–57)

For each perk: **Original hooks** (function + address), **Original behavior**, **Our implementation**, **Parity notes / fixes**.

---

## Perk 40 — Ninja

**Meta (from perks DB):**

* Prereq: Dodger
* Unlock index: 31
* Rarity: 2
* Flags: none

### Original behavior

**Hook:** `player_take_damage @ 0x00425e50`
When the player would take damage:

* If Ninja is owned: **1/3 chance** (`rand % 3 == 0`) to dodge completely (no HP loss and no “on-hit” disruption).

### Our version

**Hook:** `src/crimson/player_damage.py::player_take_damage()`

* Implements the same `rand % 3 == 0` dodge early-return.

### Parity

✅ Looks correct for Ninja itself.

---

## Perk 41 — Highlander

**Meta:**

* Unlock index: 37
* Rarity: 1

### Original behavior

**Hook:** `player_take_damage @ 0x00425e50`
Replaces normal damage:

* You **don’t lose HP** from damage.
* Instead: **10% chance** (`rand % 10 == 0`) to drop dead (sets health to `0.0`).

Hit-disruption logic (heading randomization and `spread_heat` bump) still occurs when a hit is not “dodged.”

### Our version

**Hook:** `src/crimson/player_damage.py::player_take_damage()`

* Same `rand % 10 == 0` death roll
* Otherwise ignores the damage amount

### Parity

✅ Core behavior matches.

---

## Perk 42 — Jinxed

**Meta:**

* Unlock index: 30
* Rarity: 1

### Original behavior

**Hook:** `perks_update_effects @ 0x00406b40`
Uses a global timer (`jinxed_timer`):

* Each frame: `jinxed_timer -= frame_dt`
* When it goes below 0 and perk is active:

  1. **1/10 chance** (`rand % 10 == 3`) to hurt the player: `health -= 5.0` and spawn **two random effects** at player position.
  2. Reset timer: `jinxed_timer += 2.0 + (rand % 0x14) * 0.1` (adds 2.0 .. 3.9 seconds)
  3. If Freeze bonus timer <= 0:

     * Try up to 10 random creature indices (`rand % 0x17f`) until finding an active creature.
     * Kill it by forcing **death staging** without normal death handling:

       * `creature.health = -1.0`
       * `creature.hitbox_size -= frame_dt * 20.0`
     * Award XP directly: `player.experience += creature.reward_value`
     * Play a “bonus” SFX.

### Our version

**Hook:** `src/crimson/gameplay.py::perks_update_effects()`

* Implements the same timer, same 1/10 roll, same timer reset formula
* Kills random creature with the same “set hp negative + shrink hitbox_size” trick
* Adds XP directly to player and queues an SFX

### Parity

✅ Looks correct.

---

## Perk 43 — Perk Master

**Meta:**

* Prereq: Perk Expert
* Unlock index: 24
* Rarity: 2

### Original behavior

**Hook:** perk selection UI logic (decompile around `0x0041...`; effectively “perk choice count”)

* Normally: 5 perk choices
* With Perk Expert: 6
* With Perk Master: **7**

### Our version

**Hook:** `src/crimson/gameplay.py::perk_choice_count()`

* Returns 7 if Perk Master active, else 6 if Perk Expert active, else 5.
* `perk_generate_choices()` always generates 7 and slices to the returned count.

### Parity

✅ Matches.

---

## Perk 44 — Reflex Boosted

**Meta:**

* Unlock index: 32
* Rarity: 2

### Original behavior

**Hook:** main loop / frame step
When in gameplay state and Reflex Boosted is owned:

* `frame_dt *= 0.9` (global slow motion)

### Our version

**Hook:** `src/crimson/sim/world_state.py::WorldState.step()`

* Scales `dt *= 0.9` when player 0 has the perk.

### Parity

✅ Matches for shared-perks model.

---

## Perk 45 — Greater Regeneration

**Meta:**

* Prereq: Regeneration
* Unlock index: 34
* Rarity: 2

### Original behavior

**Hooks found in this build:**

* Only referenced in Death Clock blocking / clearing:

  * Blocked in perk offers when Death Clock is active
  * Cleared when Death Clock is applied

**No actual “greater regen tick” exists in the authoritative decompile** (so in this executable, it appears to do nothing).

### Our version

* No runtime effect implemented.
* Death Clock clears it.

### Parity

✅ Matches *this* original build (i.e., “no effect”).

---

## Perk 46 — Breathing Room

**Meta:**

* Unlock index: 38
* Rarity: 2
* Flags: **two-player only**

### Original behavior

**Hook:** `perk_apply @ 0x004055e0`
When selected:

* For each player: `health -= health * 0.6666667` (leaves 1/3)
* For each active creature: `hitbox_size -= frame_dt`

  * This forces them into the “dead/staging” path without awarding XP.
* Sets `bonus_spawn_guard = 0`

### Our version

**Hook:** `src/crimson/gameplay.py::perk_apply()`

* Same health reduction
* Same creature `hitbox_size -= dt`
* Clears `bonus_spawn_guard`

### Parity

✅ Looks correct.

---

## Perk 47 — Death Clock

**Meta:**

* Unlock index: 33
* Rarity: 2

### Original behavior

**Hooks:**

* `perk_apply @ 0x004055e0`
* `player_take_damage @ 0x00425e50`
* `perks_update_effects @ 0x00406b40`
* `bonus_pick_random_type @ 0x00412470`
* perk-offer generation (death clock blocks certain perks)

Effects:

1. **On apply**:

   * Clears Regeneration + Greater Regeneration perk counts
   * Sets each alive player’s health to **100.0**
2. **Damage immunity**:

   * In `player_take_damage`: if Death Clock active, returns immediately (no damage from enemies)
3. **The actual “30 seconds to live”**:

   * In `perks_update_effects`, for each player:

     * If health <= 0: set to 0
     * Else: `health -= frame_dt * 3.3333333` (100/30 per second)
4. **No Medikits**:

   * In `bonus_pick_random_type`: Medikit is removed from the random pool while Death Clock is active
5. **Blocks perks that would undermine the clock**:

   * While Death Clock active, perk offers skip:

     * Jinxed, Breathing Room, Grim Deal, Highlander, Fatal Lottery, Ammunition Within, Infernal Contract,
       Regeneration, Greater Regeneration, Thick Skinned, Bandage (plus one redundant sentinel constant)

### Our version

**Hooks:**

* Apply + regen clearing: `src/crimson/gameplay.py::perk_apply()` ✅
* Damage immunity: `src/crimson/player_damage.py::player_take_damage()` ✅
* Medikit block: `src/crimson/gameplay.py::bonus_pick_random_type()` ✅
* Offer blocking: `src/crimson/gameplay.py::perk_generate_choices()` ✅

❌ Missing: the per-frame health drain.

### Fix suggestion

Add to `src/crimson/gameplay.py::perks_update_effects()` (near other periodic perk effects):

* For each player with perk:

  * if `health <= 0`: set `health = 0`
  * else `health -= dt * 3.3333333`

Also update the perk notes in `src/crimson/perks.py` (they currently don’t mention the drain).

---

## Perk 48 — My Favourite Weapon

**Meta:**

* Unlock index: 39
* Rarity: 2

### Original behavior

**Hooks:**

* `perk_apply @ 0x004055e0`
* `weapon_assign_player @ 0x00452d40`
* `bonus_pick_random_type @ 0x00412470`
* `bonus_try_spawn_on_kill @ 0x0041f1a0`
* `bonus_apply` also blocks picking it up if it somehow exists

Effects:

1. On apply: `clip_size += 2` (per player)
2. On any weapon assignment: also adds `+2` clip size (so it sticks even when swapping weapons)
3. Weapon bonuses cannot spawn or be selected:

   * Random bonus pick rerolls away from Weapon
   * Weapon drops on kill are cancelled
   * Picking up a Weapon bonus is ignored

### Our version

**Hooks:**

* Apply: `src/crimson/gameplay.py::perk_apply()` ✅
* Weapon assignment: `src/crimson/gameplay.py::weapon_assign_player()` ✅
* Random bonus selection: `src/crimson/gameplay.py::bonus_pick_random_type()` ✅
* “Try spawn on kill”: `src/crimson/gameplay.py::BonusPool.try_spawn_on_kill()` ✅
* Apply bonus: `src/crimson/gameplay.py::bonus_apply()` ✅

### Parity

✅ Looks correct.

---

## Perk 49 — Bandage

**Meta:**

* Unlock index: 42
* Rarity: 2

### Original behavior

**Hook:** `perk_apply @ 0x004055e0`
For each player:

* `health *= (rand % 0x32 + 1.0)` (multiplies by 1..50)
* clamp to `<= 100.0`
* spawn a burst FX (8 particles)

### Our version

**Hook:** `src/crimson/gameplay.py::perk_apply()`

* Same multiply (1..50) + clamp + burst FX

### Parity

✅ Looks correct.

---

## Perk 50 — Angry Reloader

**Meta:**

* Unlock index: 25
* Rarity: 2

### Original behavior

**Hook:** `player_update @ 0x004136b0`
During a reload, when the reload timer crosses the halfway point (from >50% to <=50%) **and** `reload_timer_max > 0.5`:

* Spawn a projectile ring:

  * Type: `PROJECTILE_TYPE_PLASMA_MINIGUN`
  * Count: `7 + int(reload_timer_max * 4.0)` (trunc toward zero)
  * Angle offset: `0.1`
* Wrap spawn in `bonus_spawn_guard = 1` / `0`
* Play `sfx_explosion_small`
* Uses the Stationary Reloader multiplier (3x) if stationary

Owner id:

* If friendly fire off: owner_id = -100
* Else: owner_id = -1 - player index

### Our version

**Hook:** `src/crimson/gameplay.py::player_update()`

* Same trigger condition (crossing halfway)
* Same count formula and ring spawn and sfx queue
* Uses stationary reload scaling

❌ owner_id doesn’t match original when friendly fire is off.

### Fix suggestion

* Add a helper that takes `state.friendly_fire_enabled` into account (or change `_owner_id_for_player` to accept state).
* Use it in angry reloader ring spawn.

---

## Perk 51 — Ion Gun Master

**Meta:**

* Unlock index: 41
* Rarity: 2

### Original behavior

**Hooks:**

* `creature_apply_damage @ 0x004207c0`
* `projectile_update @ 0x00420b90`

Effects:

* When `damage_type == 7` (ion blast), multiply damage by **1.2**
* Ion AoE radii are scaled by **1.2** for ion weapons (ion rifle / minigun / cannon)

### Our version

**Hooks:**

* `src/crimson/creatures/damage.py::creature_apply_damage()` ✅
* `src/crimson/projectiles.py` ion AoE uses `ion_scale = 1.2` ✅

### Parity

✅ Looks correct.

---

## Perk 52 — Stationary Reloader

**Meta:**

* Unlock index: 43
* Rarity: 2

### Original behavior

**Hook:** `player_update @ 0x004136b0`
If player’s position did not change this frame:

* Reload speed multiplier becomes **3.0**
  Otherwise:
* 1.0

### Our version

**Hook:** `src/crimson/gameplay.py::player_update()`

* Detects stationary by comparing prev/new position
* Applies `reload_scale = 3.0` when perk active and stationary

### Parity

✅ Looks correct.

---

## Perk 53 — Man Bomb

**Meta:**

* Unlock index: 0 (always available)
* Rarity: 1

### Original behavior

**Hook:** `player_update @ 0x004136b0`

* Timer increments while perk active
* When `man_bomb_timer > man_bomb_interval` (interval starts at 4.0):

  * owner_id = -100 if friendly fire off else -1-player index
  * Spawn **8 projectiles** in a ring from player pos:

    * Even index: ion minigun
    * Odd index: ion rifle
    * Angle per projectile: `idx*(pi/4) + ((rand%50)*0.01 - 0.25)`
  * Play `sfx_explosion_small`
  * `man_bomb_timer -= interval`
  * Reset interval to 4.0
* After movement is applied, if player moved this frame, timer is reset to 0.0
  (so it only *accumulates* while stationary, but the spawn test runs before the “reset if moved”.)

### Our version

**Hooks:**

* `src/crimson/gameplay.py::player_update()` calls `_perk_update_man_bomb()` only when stationary
* `_perk_update_man_bomb()` spawns the same 8 alternating projectiles with the same jitter

Parity issues:

1. ❌ owner_id doesn’t respect friendly fire off sentinel (-100)
2. ❌ we wrap spawn in `bonus_spawn_guard=True/False` but original doesn’t
3. (Minor) ordering: because we only update when stationary *after movement*, we won’t trigger a “threshold reached this frame while starting to move” explosion the way the original can.

### Fix suggestions

* Remove `bonus_spawn_guard` wrapping inside `_perk_update_man_bomb()`.
* Fix owner_id to -100 when friendly fire disabled.
* If you want exact timing parity: update man_bomb timer before movement, then reset if moved afterward (mirror original order).

---

## Perk 54 — Fire Caugh

**Meta:**

* Unlock index: 0 (always available)
* Rarity: 1

### Original behavior

**Hook:** `player_update @ 0x004136b0`
Every `fire_cough_interval` seconds (interval is randomized 2–5s each trigger):

* owner_id = -100 if friendly fire off else -1-player index
* Play **two** SFX
* Spawn **Fire Bullets** projectile:

  * Muzzle position uses a rotated aim direction (includes a fixed `-0.150915` rad offset)
  * Aim point is jittered by `distance * spread_heat * random_scalar` in a random direction
* Spawn a small sprite FX at muzzle moving forward (`cos(aim_heading)*25`, `sin(aim_heading)*25`) with grey/alpha tint
* Timer subtracts interval and interval is rerolled: `(rand % 4) + 2.0`

### Our version

**Hook:** `src/crimson/gameplay.py::_perk_update_fire_cough()`

* Timer and interval logic matches (subtract interval, reroll 2–5)
* Spawns Fire Bullets projectile, but:

  * Uses a small constant angle jitter unrelated to distance/spread_heat
  * Muzzle position is `pos + aim_dir*16` (no extra -0.150915 offset)
  * No sprite FX and no two SFX plays
  * owner_id uses `-1 - player_index` even when friendly fire is off

### Fix suggestion

Rewrite `_perk_update_fire_cough()` to match `player_fire_weapon()`’s aim jitter + muzzle math:

* Use the same distance-scaled jitter already implemented in `player_fire_weapon()`
* Apply the `-0.150915` muzzle rotation (as the original does)
* Add the extra sprite FX + the two SFX (if/when we have exact IDs mapped)
* Fix owner_id selection per friendly fire

---

## Perk 55 — Living Fortress

**Meta:**

* Unlock index: 0 (always available)
* Rarity: 1

### Original behavior

**Hooks:**

* `player_update @ 0x004136b0`: timer
* `creature_apply_damage @ 0x004207c0`: damage scaling

Timer:

* While perk active: `living_fortress_timer += dt`, clamp at **30.0**
* If player moved this frame: timer reset to 0.0

Damage:

* If `damage_type == 1` (bullet damage) and perk active:

  * For each alive player: `damage *= (living_fortress_timer*0.05 + 1.0)`
  * (Stacks multiplicatively across alive players.)

### Our version

* Timer: `src/crimson/gameplay.py::player_update()` (stationary → accumulate, else reset) ✅
* Damage scaling: `src/crimson/creatures/damage.py::creature_apply_damage()` ✅

### Parity

✅ Looks correct (timing order nuance is extremely minor here since there’s no discrete trigger).

---

## Perk 56 — Tough Reloader

**Meta:**

* Unlock index: 0 (always available)
* Rarity: 1

### Original behavior

**Hook:** `player_take_damage @ 0x00425e50`
If perk active **and** `reload_active != 0`:

* `damage *= 0.5` before applying

### Our version

**Hook:** `src/crimson/player_damage.py::player_take_damage()`

* Same “if reload_active: dmg *= 0.5”

### Parity

✅ Looks correct.

---

## Perk 57 — Lifeline 50-50

**Meta:**

* Unlock index: 36
* Rarity: 2

### Original behavior

**Hook:** `perk_apply @ 0x004055e0`
On apply:

* Iterates through creature pool, toggling a boolean each slot
* When toggle is “true”, and creature is:

  * active
  * `health <= 500.0`
  * `(flags & 4) == 0`
* Then it **removes** the creature instantly:

  * `active = 0`
  * spawn burst FX (4 particles)
* No XP / normal death logic (because it doesn’t call the death handler)

### Our version

**Hook:** `src/crimson/gameplay.py::perk_apply()`

* Same toggle-every-slot behavior
* Same eligibility checks (`hp <= 500`, `flags & 4 == 0`, active)
* Deactivates creature and spawns burst

### Parity

✅ Looks correct.

---

# Suggested fix locations (quick index)

* **Death Clock drain (perk 47):**
  `src/crimson/gameplay.py::perks_update_effects()`
  Add per-frame health drain `dt * 3.3333333` when Death Clock is active.

* **Fire Caugh parity (perk 54):**
  `src/crimson/gameplay.py::_perk_update_fire_cough()`
  Reuse/clone the aim jitter + muzzle logic from `player_fire_weapon()` and add the missing FX/SFX.

* **Owner-id parity for perk projectiles (perks 50, 53, 54):**
  Create `owner_id_for_player(state, player_index)` (or change `_owner_id_for_player` signature) so:

  * if `not state.friendly_fire_enabled`: return `-100`
  * else: return `-1 - player_index`
    Then use it in Angry Reloader / Man Bomb / Fire Caugh spawns.

* **Man Bomb bonus_spawn_guard (perk 53):**
  `src/crimson/gameplay.py::_perk_update_man_bomb()`
  Remove the guard wrap to mirror original.

* **(Optional) demo/full-version perk offer gating:**
  Our perk offer logic in `src/crimson/gameplay.py::perk_can_offer()` / selection flow
  Mirror `perk_can_offer @ 0x0042fb10` behavior if we care about trial fidelity.

---

If you want, I can also produce a **minimal patch plan** (exact code blocks) for the Death Clock drain + Fire Caugh rewrite + owner-id helper so you can drop it straight into `src/crimson/gameplay.py` without hunting for the right constants.
