Here’s what stands out (in your **`src/`** vs the authoritative **`analysis/`** decomp), focusing on *fidelity gaps* rather than general “still missing features”.

I’m referencing the Ghidra decompile in `analysis/ghidra/raw/crimsonland.exe_decompiled.c` and the FRIDA trace summary in `analysis/frida/weapon_switch_trace_summary.json`, and then checking how the same behaviors are represented in your Python port.

---

## 1) Weapon drops are not faithful to the original [x]

### What the original does

In the original Crimsonland binary, the weapon drop chooser is **not** “pick any named weapon”.

* `weapon_pick_random_available @ 00452cd0`:

  * picks only from weapon IDs **1..33** (`rand % 0x21 + 1`)
  * **requires** the weapon’s `weapon_table[weapon_id].unlocked != 0`
  * applies a **bias against already-used weapons**: if `weapon_usage_counts[weapon_id] != 0`, there’s a 50% chance it rerolls once (see the second `crt_rand() & 1` branch)
  * has a small quest-stage special-case (you can ignore initially, but it’s real)

* `weapon_assign_player @ 00452d40` increments persistent `game_status_blob.weapon_usage_counts[weapon_id]` (unless demo mode), which is what the drop bias uses.

### What your port does

Fixed:

* `weapon_refresh_available(state)` models the native `weapon_table[weapon_id].unlocked` flags.
* `weapon_pick_random_available(state)` matches the native 1..33 pool + unlocked gating + usage-count reroll bias.
* `weapon_assign_player(..., state=...)` bumps `status.weapon_usage_counts[weapon_id]` (unless demo mode).

**Impact:**

* Weapon bonus drops will diverge heavily (wrong pool, wrong distribution, wrong unlock gating).
* The original’s “push you toward less-used weapons” behavior is missing entirely.
* In the worst case you can drop things the original never drops as “weapon bonus” items.

**Actionable fix:**

- [x] Implement `weapon_refresh_available` logic (see next section) and store per-weapon `unlocked/available` state.
- [x] Re-implement `weapon_pick_random_available` to match the decompile:
  - [x] candidate range 1..33
  - [x] enforce unlocked
  - [x] usage-count reroll bias
- [x] Increment `status.weapon_usage_counts[weapon_id]` in the equivalent of `weapon_assign_player`.

---

## 2) Weapon availability / unlock progression is not wired into gameplay [x]

### What the original does

* `weapon_refresh_available @ 00452e40` rebuilds `weapon_table[weapon_id].unlocked` based on:

  * `game_status_blob.quest_unlock_index`
  * per-quest weapon unlock ids (`quest_selected_meta.unlock_weapon_id`)
  * special handling for survival mode defaults (it explicitly enables Assault Rifle/Shotgun/Submachine Gun in survival via hardcoded flags)

This is a key piece of progression logic.

### What your port does

Fixed: weapon availability is tracked in `GameplayState.weapon_available` and refreshed via `weapon_refresh_available(state)` using `status.quest_unlock_index` (plus Survival defaults).

**Impact:**

* Even if your UI *shows* progression, the actual drop pools and availability don’t match the original.
* Survival defaults (extra starter weapons) won’t match unless coincidentally.

**Actionable fix:**

- [x] Add a "weapon availability" table (`GameplayState.weapon_available`).
- [x] Rebuild it on game start / mode switch and when `quest_unlock_index` changes.

---

## 3) Perk availability + perk choice generation diverge from the original [x]

There are **two** distinct fidelity issues here: “what perks exist” and “how the perk choice list is generated”.

### 3a) Missing perk availability gating

Original behavior:

* `perks_rebuild_available @ 0042fc30` sets `perk_meta_table[perk_id].available` based on quest unlocks (and base/permanent perks).
* `perk_select_random` only picks from `available` perks.

Your port:

Fixed:

* `GameplayState.perk_available` tracks the native `perk_meta_table[perk_id].available` flags.
* `perks_rebuild_available(state)` rebuilds the availability table based on quest unlocks (`status.quest_unlock_index`) + base/permanent perks.
* `perk_select_random(state, ...)` only picks from available perks.

**Impact:**

* Unlocked-perk progression is not faithful; perks can appear too early.

### 3b) Perk choice generation logic is significantly simplified

Original behavior:

* `perks_generate_choices` contains several special rules, including:

  * **Death Clock**: when active, it blocks a list of other perks from being offered (the decompile has a long “if death_clock_count != 0 then disallow …” list).
  * Some perks are made rarer by an extra reroll gate (e.g. the `(rand & 3) != 1` block for a set of perks).
  * Quest-stage special-case insertion for Monster Vision.

Your port:

Fixed: `perk_generate_choices` now mirrors the decompile’s selection quirks:

* Death Clock blocks the native list of perks from being offered.
* rarity rerolls (`(rand & 3) == 1` rejection) for the gated perk set.
* quest 1-7 Monster Vision insertion.
* Pyromaniac gating (only offered when Flamethrower is equipped).
* tutorial mode override list.

**Impact:**

* Even if perk effects are correct once owned, the *distribution and gating* of perk choices will not feel like the original.

**Actionable fix:**

- [x] Implement:
  - [x] `perks_rebuild_available` equivalent (quest unlock driven)
  - [x] original `perk_can_offer` rules (especially Death Clock restrictions)
  - [x] original `perk_generate_choices` quirks (rarity rerolls + quest special cases)

---

## 4) Weapon ammo class is currently missing, affecting HUD + perk economics [x]

Fixed: weapon entries now have `ammo_class` populated (at least 1..33), sourced from:

* `analysis/frida/weapon_switch_trace_summary.json` (for weapons seen in the trace)
* `weapon_table_init @ 004519b0` ammo-class table writes (for missing ids in 1..33)

You already have multiple systems that consult this:

* HUD ammo indicator selection (`src/crimson/ui/hud.py` uses `_weapon_ammo_class()`)
* perk/bonus balancing (e.g., Regression Bullets / Ammunition Within costs differ by ammo class in the original)
* the decomp and docs indicate ammo class is also used in some projectile hit-effect gating.

This also removes the need for the Flamethrower ammo-class workaround in reload-firing perk costs (Regression Bullets / Ammunition Within).

### You already have authoritative ammo_class values for many weapons

From `analysis/frida/weapon_switch_trace_summary.json`, ammo class values are known for a big chunk of core weapons. Example subset:

| weapon_id | weapon name     | ammo_class |
| --------: | --------------- | ---------: |
|         1 | Pistol          |          0 |
|         2 | Assault Rifle   |          0 |
|         3 | Shotgun         |          0 |
|         4 | Sawed-Off       |          0 |
|         5 | Submachine Gun  |          0 |
|         6 | Gauss Gun       |          0 |
|         7 | Minigun         |          0 |
|         8 | Flamethrower    |          1 |
|        12 | Rocket Launcher |          2 |
|        13 | Seeker Rockets  |          2 |
|        15 | Blow Torch      |          1 |
|        18 | Rocket Minigun  |          2 |
|        19 | Pulse Gun       |          3 |
|        21 | Ion Rifle       |          4 |
|        22 | Ion Minigun     |          4 |
|        23 | Ion Cannon      |          4 |
|        28 | Plasma Cannon   |          0 |
|        31 | Ion Shotgun     |          4 |

(That file contains more; you can fill in a lot without guessing.)

**Impact:**

* Wrong ammo HUD icons
* Wrong perk cost/benefit scaling in places that depend on ammo class
* Potentially wrong visual effects gating

**Actionable fix:**

- [x] Populate `ammo_class` for weapons at least 1..33 immediately (from the FRIDA trace + a quick additional dump if needed).
- [x] Remove the Flamethrower special-case once you have correct data.

---

## 5) Two weapon names are missing in your weapon table [x]

Fixed:

* weapon 33 name is **RayGun**
* weapon 52 name is **Lighting Rifle** (note: original string is “Lighting”, not “Lightning”)

You can see both names being copied in `weapon_table_init @ 004519b0` in the Ghidra decompile:

* `&DAT_004793f4` copied into `DAT_004d8a28` → weapon 33
* `s___Lighting_Rifle_... + 2` copied into `DAT_004d935c` → weapon 52

**Impact:**

* UI display gaps (arsenal/debug views)
* your `_WEAPON_RANDOM_IDS` construction currently *excludes* these because it filters by `name is not None` (even though the original weapon picker doesn’t work that way, this still affects current behavior)

**Actionable fix:**

- [x] Fill the missing names.

---

## 6) Speed bonus multiplier doesn't match the decompile [x]

Fixed: `player_update` applies the speed bonus via the native additive model (`+1.0` to the speed multiplier while the timer is active), instead of multiplying the final speed by `1.35`.

In the original `player_update @ 004136b0`, speed bonus works by temporarily doing:

* `speed_multiplier = speed_multiplier + 1.0` while the timer is active
* later subtracting it back out

Given the baseline `speed_multiplier` is typically 2.0, the original effect is effectively **1.5×**, not **1.35×**.

**Impact:**

* Speed bonus feels wrong; also indirectly affects animation phase and anything derived from move speed.

**Actionable fix:**

- [x] Change to the additive model, or at minimum adjust the factor to 1.5× if your simplified model intentionally avoids the original's acceleration curves.

---

## 7) Weapon assignment side effects are missing (sound + latch/timer) [x]

Original `weapon_assign_player @ 00452d40` does more than “set weapon id & ammo”:

* increments `weapon_usage_counts[weapon_id]` (unless demo)
* clears `player_weapon_reset_latch`
* sets `player_aux_timer = 2.0`
* plays the weapon’s **reload SFX** immediately (`sfx_play_panned(weapon.reload_sfx_id)`)

Fixed:

* `weapon_assign_player(..., state=...)` bumps persistent usage counts (unless demo).
* Weapon assignment clears `weapon_reset_latch` and sets `aux_timer = 2.0`.
* Weapon assignment queues the weapon reload SFX (equip sound) explicitly.

**Impact:**

* Weapon switching sounds differ from the original
* Any behavior tied to those timers/latches is missing (even if subtle)

**Actionable fix:**

- [x] Decide where "weapon switch SFX" belongs in your architecture:
  - [x] emit an explicit SFX event from `weapon_assign_player`
- [x] Add the missing latch/timer fields if they're used elsewhere in the original's logic.

---

## 8) Quest-mode bonus suppression rules are missing in `bonus_pick_random_type` [x]

Your `bonus_pick_random_type()` matches the general 162-roll distribution and most suppression rules, **but not** the quest-stage-specific suppressions mentioned in your own docs (and visible in the decompile `bonus_pick_random_type @ 00412470`).

The original suppresses:

* **Freeze** in some quest stages
* **Nuke** in some quest stages

Fixed: `bonus_pick_random_type` now applies the quest-stage suppressions for Freeze and Nuke (quest mode, stage `*-10`) as in the decompile.

**Impact:**

* Quest mode random bonus behavior diverges (if/when quests use this path)

---

## 9) Two smaller but concrete fidelity risks [ ]

### 9a) Demo idle attract threshold is still a guess [ ]

`src/crimson/frontend/menu.py` sets:

```py
MENU_DEMO_IDLE_START_MS = 30000  # TODO: confirm via frida tracing
```

If you’re aiming for high fidelity, this should be sourced from the original (your comment already flags it).

### 9b) Hardcore quest highscores filename is marked as uncertain [x]

`src/crimson/persistence/highscores.py` has an explicit TODO/comment questioning whether hardcore quest scores should use `questhcXX.dat` (line ~267).

If you want faithful persistence interoperability with original files, this matters.

Fixed: quest-mode highscores now match the native `highscore_build_path` behavior:

- non-hardcore quests use `questhc{major}_{minor}.hi`
- hardcore quests use `quest{major}_{minor}.hi`

---

## Highest value next steps (in order)

- [x] 1. **Fix weapon drops**:
  - [x] implement weapon availability (`weapon_refresh_available`) + usage counts bump
  - [x] reimplement `weapon_pick_random_available` to match the original algorithm and pool (1..33)

- [x] 2. **Implement perk availability + original perk offering rules**:
  - [x] `perks_rebuild_available`
  - [x] Death Clock offer restrictions
  - [x] rarity rerolls / special cases (Monster Vision quest insert)

- [x] 3. **Fill `ammo_class` for weapons** (you already have many in the FRIDA trace summary)

- [x] 4. **Correct Speed bonus scaling** (1.5× effective behavior)

- [x] 5. **Fill missing weapon names** (RayGun, Lighting Rifle)

- [x] 6. **Weapon-switch side effects** (reload SFX + latch/timer) if you care about near-perfect "feel"

If you want, I can also give you a “diff-style” pseudo-patch outline for the weapon/perk selection functions that mirrors the decompile closely (without changing your broader architecture).

---

I went through the zip and cross-checked your current Python implementation against the authoritative Ghidra decompile that’s included (`analysis/ghidra/raw/crimsonland.exe_decompiled.c`). The biggest inconsistencies I found match your suspicion: **weapon firing → projectile/effect spawning is currently driven by outdated assumptions**, and that cascades into “wrong projectiles / wrong effects / wrong HUD info”.

Below are the concrete inconsistencies (with pointers to *where* the native behavior is shown and *where* your code currently diverges).

---

## 1) Critical: projectile `type_id` is not "0-based"; it's the weapon-table index the native code uses [x]

### What native does

Native `projectile_spawn(pos, angle, type_id, owner_id)` **indexes the weapon table using `type_id`** to pull projectile meta and damage scale:

* `base_damage = weapon_table[type_id].projectile_meta`
* `damage_scale = weapon_table[type_id].damage_scale`

You can see this directly in `projectile_spawn`:

* `analysis/ghidra/raw/crimsonland.exe_decompiled.c` around lines **18772–18779** (numbered in the file by `nl -ba`) show:

  * `(&projectile_pool)[iVar2].base_damage = (&weapon_table)[type_id].projectile_meta;`
  * `(&projectile_pool)[iVar2].damage_scale = (&weapon_table)[type_id].damage_scale;`

This also explains why the trace sees pistol bullets as `type_id == 1`, assault rifle as `2`, etc.

### What your code does now

Fixed: projectile `type_id` values are treated as weapon-table indices (native).

* `src/crimson/weapons.py`:
  * `projectile_type_id_from_weapon_id(weapon_id)` returns the native projectile `type_id` (or `None` for non-projectile weapons).
  * `weapon_entry_for_projectile_type_id(type_id)` indexes `WEAPON_BY_ID[type_id]` directly.

### Why this is a big deal

Because native uses `type_id` to index the weapon table, **the numeric IDs must match native** or you’ll be reading the wrong projectile meta/damage scale, and all the per-type special casing (ion radii, fire bullets, splitter, gauss shotgun, etc.) will be off.

This single mismatch can manifest exactly like what you described:

* projectiles “look wrong”
* hit radii feel wrong (ion weapons in particular)
* secondary effects and trails seem off

---

## 2) Weapon firing behavior in `player_fire_weapon` is substantially different from native `player_update` [x]

Native firing logic lives in `player_update` (not in your Python `player_fire_weapon`), and it has a **per-weapon “spawn path table”** that you currently don’t match.

The native weapon switch inside `player_update` shows exactly what each weapon does. The key section is:

* `analysis/ghidra/raw/crimsonland.exe_decompiled.c` around **12934–13410** (weapon cases),
  and the Fire Bullets override path around **13416–13510**.

### Major mismatches by weapon

I’m listing *native behavior → your behavior*, and the *native evidence lines*.

#### Weapon 8: Flamethrower [x]

* **Native:** spawns **fast particles** (`fx_spawn_particle`), ammo drain **0.1**
  Evidence: **13061–13064** (`iVar10 == 8` → `fx_spawn_particle(...); local_38 = 0.1`)
* **Yours:** Flamethrower falls into the generic projectile path (no special-case) and fires "normal projectiles".
  Code: `src/crimson/gameplay.py` — no `weapon_id == 8` particle branch.

#### Weapon 9: Plasma Rifle [x]

* **Native:** spawns a **projectile**: `projectile_spawn(..., 9, owner)`
  Evidence: **13114–13116** (`iVar10 == 9`)
* **Yours:** treated as a **fast particle weapon** (style 0), fractional drain
  Code: `src/crimson/gameplay.py` branch `elif player.weapon_id == 9: # Plasma Rifle -> fast particle weapon`

#### Weapon 10: Multi-Plasma [x]

* **Native:** spawns **five projectiles** mixing type **9** and type **0x0B**
  Evidence: **13117–13132**
* **Yours:** generic single projectile (or generic pellet logic depending on your weapon entry), no 5-shot pattern.

#### Weapon 11: Plasma Minigun [x]

* **Native:** `projectile_spawn(..., 0x0B, owner)`
  Evidence: **13176–13178**
* **Yours:** generic path using your 0-based type mapping (so it will not be `0x0B` in the native sense).

#### Weapon 12: Rocket Launcher [x]

* **Native:** spawns **secondary projectile type 1** (`fx_spawn_secondary_projectile(..., 1)`), drain 1 ammo
  Evidence: **13272–13275**
* **Yours:** generic main projectile path (not secondary)
  Code: you don't special-case weapon 12 at all.

#### Weapon 13: Seeker Rockets [x]

* **Native:** spawns **secondary projectile type 2** (homing) + also spawns a sprite burst
  Evidence: **13342–13348**
* **Yours:** spawns secondary type **1**
  Code: `elif player.weapon_id == 13: secondary_type_id = SecondaryProjectileTypeId.SEEKER_ROCKET` (you define that as 1)

#### Weapon 14: Plasma Shotgun [x]

* **Native:** fires **14** projectiles of type **0x0B** with jitter `0.002` and per-pellet `speed_scale = 1.0..1.99`
  Evidence: **13372–13387**
* **Yours:** spawns a secondary projectile (type 2)
  Code: `elif player.weapon_id == 14: secondary_type_id = SecondaryProjectileTypeId.PLASMA_SHOTGUN`

#### Weapon 15: Blow Torch [x]

* **Native:** spawns **fast particle** then sets `style_id = 1`, drain **0.05**
  Evidence: **13048–13053**
* **Yours:** not special-cased → generic projectile path

#### Weapon 16: HR Flamer [x]

* **Native:** spawns **fast particle**, sets `style_id = 2`, drain **0.1**
  Evidence: **13042–13047**
* **Yours:** `weapon_id == 16` uses fast particle but sets `style_id = 1` and drain `0.05`
  Code: `src/crimson/gameplay.py` branch `elif player.weapon_id == 16: ... style_id = 1 ... ammo_cost = 0.05`

#### Weapon 17: Mini-Rocket Swarmers [x]

* **Native:** spawns **N** secondary projectiles **type 2** in a fan based on *current ammo*, then drains *all ammo* in the clip
  Evidence: **13312–13325**
* **Yours:** treated as fast particle weapon style 2
  Code: `elif player.weapon_id == 17: # Mini-Rocket Swarmers -> fast particle weapon (style 2)`

#### Weapon 18: Rocket Minigun [x]

* **Native:** spawns **secondary type 4**, drain 1 ammo
  Evidence: **13326–13329**
* **Yours:** spawns secondary type 2 and drains whole clip (rocket swarmers behavior)
  Code: `elif player.weapon_id == 18: secondary_type_id = SecondaryProjectileTypeId.PLASMA_SHOTGUN; ammo_cost = float(player.ammo)`

#### Weapon 19: Pulse Gun [x]

* **Native:** `projectile_spawn(..., 0x13, owner)` (main projectile), not a secondary
  Evidence: **13148–13150**
* **Yours:** secondary projectile type 4
  Code: `elif player.weapon_id == 19: secondary_type_id = SecondaryProjectileTypeId.PULSE_GUN`

#### Weapon 20: Jackhammer [x]

* **Native:** uses **shotgun projectile type 3**, spawns **4** pellets with jitter `0.0013` and speed_scale random `1.0..1.99`
  Evidence: **13014–13039**
* **Yours:** generic pellet_count logic, but using your own derived type id — so it's not using template 3 as native does.

#### Weapon 30: Gauss Shotgun [x]

* **Native:** spawns **8** gauss projectiles of type **6** with jitter `0.0026`, speed_scale `1.4..1.89`
  Evidence: **13180–13205**
* **Yours:** generic path; not the "8× type 6" pattern.

#### Weapon 31: Ion Shotgun [x]

* **Native:** spawns **8** ion-minigun projectiles of type **0x16** with jitter `0.0026`, speed_scale `1.4..1.89`
  Evidence: **13161–13175**
* **Yours:** generic path; not this pattern.

#### Weapon 42: Bubblegun [x]

* **Native:** uses **slow particle** (`fx_spawn_particle_slow`), drain `0.15`
  Evidence: **13399–13403** and `fx_spawn_particle_slow` sets `style_id = 8` always (see **18688–18705**)
* **Yours:** not special-cased → generic projectile path.

#### Weapon 43: Rainbow Gun [x]

* **Native:** `projectile_spawn(..., 0x2B, owner)` (main projectile)
  Evidence: **13392–13398**
* **Yours:** treated as slow particle weapon style 8
  Code: `elif player.weapon_id == 43: # Rainbow Gun -> slow particle weapon style 8`

---

## 3) Perk / bonus projectile spawns use the wrong projectile IDs right now [x]

Because the projectile type ID scheme is off, perks that spawn projectiles by numeric ID are also off.

### Man Bomb perk [x]

* **Native:** alternates projectile types **0x16** and **0x15**
  Evidence: `player_update` perk logic **11772–11782**
* **Yours:** alternates **ION_MINIGUN (0x16)** and **ION_RIFLE (0x15)**
  Code: `src/crimson/gameplay.py` `_perk_update_man_bomb`

### Hot Tempered perk [x]

* **Native:** alternates projectile types **0x0B** and **0x09**
  Evidence: **11860–11870**
* **Yours:** alternates **PLASMA_MINIGUN (0x0B)** and **PLASMA_RIFLE (0x09)**
  Code: `src/crimson/gameplay.py` `_perk_update_hot_tempered`

### Fire Cough perk [x]

* **Native:** spawns projectile type **0x2D** (`projectile_spawn(..., 0x2d, ...)`)
  Evidence: **11852–11859**
* **Yours:** uses `ProjectileTypeId.FIRE_BULLETS` (native `0x2D`).

---

## 4) Effects style/type mapping in docs doesn't match the decompile (and your code followed docs) [ ]

Your `effects.py` implementation of the pools looks structurally fine, but the *weapon→style* mapping in gameplay is off because the docs are off.

Concrete evidence:

* `fx_spawn_particle` always sets `style_id = 0` (see `analysis/...` **18640–18684**) — weapon code changes it afterward.
* Blowtorch sets particle style to **1** (**13048–13053**)
* HR Flamer sets particle style to **2** (**13042–13047**)
* Slow particles always use `style_id = 8` (`fx_spawn_particle_slow` **18688–18705**) and are used by Bubblegun (**13399–13403**)

So:

* Bubblegun ≠ “rainbow slow particle” (it’s the one using slow particle style 8)
* Flamethrower uses fast particle style 0 (not plasma rifle)

---

## 5) HUD / panel rendering likely wrong because `ammo_class` is not populated [x]

Fixed: `ammo_class` is now populated in the weapon table (at least 1..33), so:

* HUD uses ammo_class to choose the ammo icon (`src/crimson/ui/hud.py` `_weapon_ammo_class`)
* various logic (and native audio) uses ammo class to select hit sounds, etc.

The trace summary already contains ammo_class values per weapon (e.g., rockets vs electric), and the remaining gaps in 1..33 are filled from `weapon_table_init`.

This can absolutely show up as “panel rendering wrong” (wrong ammo icon) even if the panel layout is otherwise fine.

---

## 6) Screen/panel gap that's still explicitly missing: game-over transition timeline [ ]

You’ve got `docs/rewrite/game-over.md` explicitly stating the **transition timeline + full SFX parity** are still missing. If you’re seeing “screen feels wrong / panels appear abruptly”, that’s consistent with this being unimplemented.

---

# Recommended fix order (to unblock golden-oracle validation)

## A) Unify projectile `type_id` semantics with native (stop doing "weapon_id - 1") [x]

This is the root-cause fix.

Concrete steps:

- [x] 1. **Change projectile IDs to match native weapon-table indexing**
  - [x] Update `ProjectileTypeId` to use native IDs (pistol = 1, assault = 2, …)
  - [x] Remove or quarantine `projectile_type_id_from_weapon_id` and `weapon_id_from_projectile_type_id` (they bake in the wrong assumption).

- [x] 2. Update every subsystem that uses projectile IDs:
  - [x] `src/crimson/projectiles.py` (spawn specials: ion radii, gauss/fire/blade damage_pool, splitter type check, etc.)
  - [x] `src/crimson/sim/world_defs.py` (`KNOWN_PROJ_FRAMES`)
  - [x] `src/crimson/render/world_renderer.py` (any type-based branching like bullet trails / ion rendering)
  - [x] perks (`_perk_update_*`)

This will immediately make your golden-oracle traces line up without constant “+1/-1 mapping”.

## B) Replace `player_fire_weapon`'s weapon switch with the native one [x]

Implement weapon behavior exactly as in the decompile section:

* `analysis/...` **12934–13410** for normal firing
* **13416–13510** for Fire Bullets override

If you want a clean architecture: encode the weapon fire behavior into a data-driven “fire profile” table (spawn kind, template ids, pellet counts, jitter, speed_scale ranges, ammo drain) to avoid a huge if/elif chain.

## C) Fix perk spawns that hardcode projectile IDs [x]

At least:

- [x] Man Bomb
- [x] Hot Tempered
- [x] Fire Cough

Use the native IDs and templates.

## D) Populate `ammo_class` in weapon definitions [x]

Use either:

* the weapon trace summary values (already in `analysis/frida/weapon_switch_trace_summary.json`)
* or lift it from the native table if you have it mapped

This will fix HUD/panel ammo icons and some audio decisions.

## E) Then re-check UI "panel rendering" [ ]

Once the ammo_class and weapon previews are correct, re-evaluate what still feels off in UI. The likely remaining big one is:

* game-over transition timeline and SFX sequence.

---

# Quick "smoking gun" checklist you can use to validate after changes

Once you fix A+B, verify these in a deterministic test harness:

- [x] Firing **Flamethrower (weapon 8)** creates **particles**, not bullets.
- [x] Firing **Plasma Rifle (weapon 9)** creates **projectiles type 9**.
- [x] **Rocket Launcher (12)** spawns **secondary type 1**, **Seeker Rockets (13)** spawns **secondary type 2**.
- [x] **Mini-Rocket Swarmers (17)** drains the whole clip and spawns that many type-2 secondaries in a fan.
- [x] **Rocket Minigun (18)** spawns **secondary type 4** per shot.
- [x] **Bubblegun (42)** spawns **slow particles style 8**.
- [x] **Rainbow Gun (43)** spawns **projectiles type 0x2B** (not slow particles).

If any of those are still wrong, something in the mapping is still off.

---

If you want, I can also generate a compact “native fire-spec table” (weapon_id → spawn kind + template ids + counts + jitter + speed_scale range + ammo drain) from the decompile section so you can wire it in as data instead of a long conditional chain.
