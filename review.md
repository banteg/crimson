Here’s what stands out (in your **`src/`** vs the authoritative **`analysis/`** decomp), focusing on *fidelity gaps* rather than general “still missing features”.

I’m referencing the Ghidra decompile in `analysis/ghidra/raw/crimsonland.exe_decompiled.c` and the FRIDA trace summary in `analysis/frida/weapon_switch_trace_summary.json`, and then checking how the same behaviors are represented in your Python port.

---

## 1) Weapon drops are not faithful to the original

### What the original does

In the original Crimsonland binary, the weapon drop chooser is **not** “pick any named weapon”.

* `weapon_pick_random_available @ 00452cd0`:

  * picks only from weapon IDs **1..33** (`rand % 0x21 + 1`)
  * **requires** the weapon’s `weapon_table[weapon_id].unlocked != 0`
  * applies a **bias against already-used weapons**: if `weapon_usage_counts[weapon_id] != 0`, there’s a 50% chance it rerolls once (see the second `crt_rand() & 1` branch)
  * has a small quest-stage special-case (you can ignore initially, but it’s real)

* `weapon_assign_player @ 00452d40` increments persistent `game_status_blob.weapon_usage_counts[weapon_id]` (unless demo mode), which is what the drop bias uses.

### What your port does

In `src/crimson/gameplay.py`:

* `weapon_pick_random_available()` (line ~1013) selects from `_WEAPON_RANDOM_IDS`, which is built from “all entries in `WEAPON_TABLE` with `name != None`”.
* `_WEAPON_RANDOM_IDS` currently includes IDs **outside 1..33** (including “bonus weapons” / dev/secret entries like Fire Bullets etc. if they have a name), and it **does not** consult any “unlocked/available” flag or usage history.
  That’s a large fidelity mismatch.

**Impact:**

* Weapon bonus drops will diverge heavily (wrong pool, wrong distribution, wrong unlock gating).
* The original’s “push you toward less-used weapons” behavior is missing entirely.
* In the worst case you can drop things the original never drops as “weapon bonus” items.

**Actionable fix:**

* Implement `weapon_refresh_available` logic (see next section) and store per-weapon `unlocked/available` state.
* Re-implement `weapon_pick_random_available` to match the decompile:

  * candidate range 1..33
  * enforce unlocked
  * usage-count reroll bias
* Increment `status.weapon_usage_counts[weapon_id]` in the equivalent of `weapon_assign_player`.

---

## 2) Weapon availability / unlock progression is not wired into gameplay

### What the original does

* `weapon_refresh_available @ 00452e40` rebuilds `weapon_table[weapon_id].unlocked` based on:

  * `game_status_blob.quest_unlock_index`
  * per-quest weapon unlock ids (`quest_selected_meta.unlock_weapon_id`)
  * special handling for survival mode defaults (it explicitly enables Assault Rifle/Shotgun/Submachine Gun in survival via hardcoded flags)

This is a key piece of progression logic.

### What your port does

I didn’t find a runtime equivalent that:

* clears + rebuilds “weapon unlocked/available” flags
* uses `status.quest_unlock_index` to affect weapon drop/availability

Your quest completion flow updates `quest_unlock_index` (e.g. `QuestResultsView`), but it doesn’t trigger any rebuild of weapon availability, and your weapon drop picker ignores unlock state anyway.

**Impact:**

* Even if your UI *shows* progression, the actual drop pools and availability don’t match the original.
* Survival defaults (extra starter weapons) won’t match unless coincidentally.

**Actionable fix:**

* Add a “weapon availability” table (either:

  * add `unlocked` to your `Weapon` metadata at runtime, or
  * keep a separate `available_weapon_ids` set/bitset in game state)
* Rebuild it:

  * on game start / mode switch
  * whenever `quest_unlock_index` changes

---

## 3) Perk availability + perk choice generation diverge from the original

There are **two** distinct fidelity issues here: “what perks exist” and “how the perk choice list is generated”.

### 3a) Missing perk availability gating

Original behavior:

* `perks_rebuild_available @ 0042fc30` sets `perk_meta_table[perk_id].available` based on quest unlocks (and base/permanent perks).
* `perk_select_random` only picks from `available` perks.

Your port:

* There is no `available` flag equivalent; perk selection is operating on “all perks in `PERK_TABLE`” (subject only to your simplified `perk_can_offer`).

**Impact:**

* Unlocked-perk progression is not faithful; perks can appear too early.

### 3b) Perk choice generation logic is significantly simplified

Original behavior:

* `perks_generate_choices` contains several special rules, including:

  * **Death Clock**: when active, it blocks a list of other perks from being offered (the decompile has a long “if death_clock_count != 0 then disallow …” list).
  * Some perks are made rarer by an extra reroll gate (e.g. the `(rand & 3) != 1` block for a set of perks).
  * Quest-stage special-case insertion for Monster Vision.

Your port:

* `perk_generate_choices()` in `src/crimson/gameplay.py` (lines ~699–716) is a uniform “sample without replacement” from a pool computed by your `perk_can_offer()`.
* Your `perk_can_offer()` (lines ~550+) does **not** encode the big Death Clock interaction rules or the “rarity reroll” behavior from the original.

**Impact:**

* Even if perk effects are correct once owned, the *distribution and gating* of perk choices will not feel like the original.

**Actionable fix:**

* Implement:

  * `perks_rebuild_available` equivalent (quest unlock driven)
  * original `perk_can_offer` rules (especially Death Clock restrictions)
  * original `perk_generate_choices` quirks (rarity rerolls + quest special cases)

---

## 4) Weapon ammo class is currently missing, affecting HUD + perk economics

In `src/crimson/weapons.py`, every weapon has `ammo_class=None` today.

You already have multiple systems that consult this:

* HUD ammo indicator selection (`src/crimson/ui/hud.py` uses `_weapon_ammo_class()`)
* perk/bonus balancing (e.g., Regression Bullets / Ammunition Within costs differ by ammo class in the original)
* the decomp and docs indicate ammo class is also used in some projectile hit-effect gating.

You currently “paper over” one case (Flamethrower) with a special-case in `_weapon_ammo_class()`, but for fidelity you need the real values.

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

* Populate `ammo_class` for weapons at least 1..33 immediately (from the FRIDA trace + a quick additional dump if needed).
* Remove the Flamethrower special-case once you have correct data.

---

## 5) Two weapon names are missing in your weapon table

In `src/crimson/weapons.py`:

* `weapon_id=33` has `name=None` but should be **RayGun**.
* `weapon_id=52` has `name=None` but should be **Lighting Rifle** (note: original string is “Lighting”, not “Lightning”).

You can see both names being copied in `weapon_table_init @ 004519b0` in the Ghidra decompile:

* `&DAT_004793f4` copied into `DAT_004d8a28` → weapon 33
* `s___Lighting_Rifle_... + 2` copied into `DAT_004d935c` → weapon 52

**Impact:**

* UI display gaps (arsenal/debug views)
* your `_WEAPON_RANDOM_IDS` construction currently *excludes* these because it filters by `name is not None` (even though the original weapon picker doesn’t work that way, this still affects current behavior)

**Actionable fix:**

* Fill the missing names.

---

## 6) Speed bonus multiplier doesn’t match the decompile

In your `player_update`:

```py
speed = 120.0 * (player.move_speed_multiplier + runner_bonus)
if player.speed_bonus_timer > 0.0:
    speed *= 1.35  # current
```

(`src/crimson/gameplay.py` lines ~1534–1536)

In the original `player_update @ 004136b0`, speed bonus works by temporarily doing:

* `speed_multiplier = speed_multiplier + 1.0` while the timer is active
* later subtracting it back out

Given the baseline `speed_multiplier` is typically 2.0, the original effect is effectively **1.5×**, not **1.35×**.

**Impact:**

* Speed bonus feels wrong; also indirectly affects animation phase and anything derived from move speed.

**Actionable fix:**

* Change to the additive model, or at minimum adjust the factor to 1.5× if your simplified model intentionally avoids the original’s acceleration curves.

---

## 7) Weapon assignment side effects are missing (sound + latch/timer)

Original `weapon_assign_player @ 00452d40` does more than “set weapon id & ammo”:

* increments `weapon_usage_counts[weapon_id]` (unless demo)
* clears `player_weapon_reset_latch`
* sets `player_aux_timer = 2.0`
* plays the weapon’s **reload SFX** immediately (`sfx_play_panned(weapon.reload_sfx_id)`)

Your `weapon_assign_player()` resets ammo/timers and applies perk adjustments, but:

* does **not** play reload SFX on weapon switch
* does not model `weapon_reset_latch` or `aux_timer`
* does not bump persistent usage counts

**Impact:**

* Weapon switching sounds differ from the original
* Any behavior tied to those timers/latches is missing (even if subtle)

**Actionable fix:**

* Decide where “weapon switch SFX” belongs in your architecture:

  * emit an explicit SFX event from `weapon_assign_player`, or
  * have the caller enqueue it after assignment
* Add the missing latch/timer fields if they’re used elsewhere in the original’s logic.

---

## 8) Quest-mode bonus suppression rules are missing in `bonus_pick_random_type`

Your `bonus_pick_random_type()` matches the general 162-roll distribution and most suppression rules, **but not** the quest-stage-specific suppressions mentioned in your own docs (and visible in the decompile `bonus_pick_random_type @ 00412470`).

The original suppresses:

* **Freeze** in some quest stages
* **Nuke** in some quest stages

Your version doesn’t check quest stage at all when deciding bonus type.

**Impact:**

* Quest mode random bonus behavior diverges (if/when quests use this path)

---

## 9) Two smaller but concrete fidelity risks

### 9a) Demo idle attract threshold is still a guess

`src/crimson/frontend/menu.py` sets:

```py
MENU_DEMO_IDLE_START_MS = 30000  # TODO: confirm via frida tracing
```

If you’re aiming for high fidelity, this should be sourced from the original (your comment already flags it).

### 9b) Hardcore quest highscores filename is marked as uncertain

`src/crimson/persistence/highscores.py` has an explicit TODO/comment questioning whether hardcore quest scores should use `questhcXX.dat` (line ~267).

If you want faithful persistence interoperability with original files, this matters.

---

## Highest value next steps (in order)

1. **Fix weapon drops**:

   * implement weapon availability (`weapon_refresh_available`) + usage counts bump
   * reimplement `weapon_pick_random_available` to match the original algorithm and pool (1..33)

2. **Implement perk availability + original perk offering rules**:

   * `perks_rebuild_available`
   * Death Clock offer restrictions
   * rarity rerolls / special cases (Monster Vision quest insert)

3. **Fill `ammo_class` for weapons** (you already have many in the FRIDA trace summary)

4. **Correct Speed bonus scaling** (1.5× effective behavior)

5. **Fill missing weapon names** (RayGun, Lighting Rifle)

6. **Weapon-switch side effects** (reload SFX + latch/timer) if you care about near-perfect “feel”

If you want, I can also give you a “diff-style” pseudo-patch outline for the weapon/perk selection functions that mirrors the decompile closely (without changing your broader architecture).
