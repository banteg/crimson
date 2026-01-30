I dug through the three “truth sources” you described:

* **docs/** (what you’ve already written down as intent/spec)
* **analysis/** (the authoritative behavior via decomp + traces)
* **src/** (what you currently run)

Below is (1) a concrete list of the biggest **remaining fidelity gaps / inconsistencies** I can see right now (including several that aren’t called out in `docs/rewrite/status.md` yet), and then (2) a **detailed, staged work plan** to close them in a way that keeps you high‑fidelity and testable.

---

## What’s already in good shape

This matters because it tells you what *not* to churn:

* **Quest building / tier wiring** looks mature and heavily tested (tier selection, spawn IDs, snapshot stability).
* **Spawn templates** are comprehensively mapped (0x00–0x43 minus the known hole).
* **Terrain / decals pipeline** is largely parity‑aligned and already has dedicated rewrite docs and tests.
* **FX queue render ordering** and some player/creature render pivots have trace-backed validation in `analysis/frida/*_trace_summary.json`.

So the remaining work is much less “missing tables/data” and much more “missing runtime semantics + event timing”.

---

## High-impact inconsistencies and gaps in `src/`

### 1) Creature damage + death timing is currently wrong (core fidelity blocker)

In the original, **damage application is not “just subtract HP”**.

In `analysis/ghidra/raw/crimsonland.exe_decompiled.c`, the function you’ve named `creature_apply_damage` (FUN_004207c0) does all of this:

* sets **hit flash timer**
* applies **perk-dependent damage scaling** (Uranium Filled Bullets, Living Fortress scaling, Barrel Greaser, Doctor, Ion Gun Master, Pyromaniac…)
* applies **knockback impulse**
* and, crucially: **if health drops <= 0, it immediately calls `creature_handle_death`** (FUN_0041e910)

Your current port mostly does:

* projectile hits → subtract `creature.hp` (in `src/crimson/projectiles.py`)
* later, on the next `CreaturePool.update()` pass, dead creatures are “noticed” and `_start_death()` is run

That creates several fidelity problems:

* **One-frame (or more) delay** between kill and kill side-effects (xp gain, bonus drops, corpse removal, perk triggers).
* **Kill attribution** is currently effectively “player 0 did it” (because death handling uses `players[0]` in `_start_death()`), and you don’t consistently set `CreatureState.last_hit_owner_id`.
* Any original logic that depends on “death happens during projectile update” will diverge (and the decomp strongly suggests it does).

This is the #1 architecture mismatch to fix because it cascades into perks, bonuses, survival leveling, SFX timing, and “feel”.

---

### 2) Several perk-triggered projectile bursts are using the wrong projectile type IDs

These are not “small tuning” issues — the **wrong projectile type** means wrong damage, wrong hit behavior, wrong effects, and wrong sound hooks.

Comparisons against the decompile show:

#### Man Bomb

* **Original** alternates **type_id 0x16** and **0x15** (see the Man Bomb block around the `perk_id_man_bomb` logic in the decompile).
* **Your code** alternates **0x14** and **0x15** in `_perk_update_man_bomb()` (`src/crimson/gameplay.py`).

#### Hot Tempered

* **Original** alternates **type_id 0x0B** and **0x09**.
* **Your code** alternates **0x08** and **0x0A** in `_perk_update_hot_tempered()`.

#### Angry Reloader

* **Original** spawns **type_id 0x0B**.
* **Your code** spawns **type_id 0x0A** when crossing the half‑reload threshold.

Also: the original plays an explosion SFX for these bursts; your implementations currently don’t.

These are “easy” but high-value fixes because they affect gameplay constantly once those perks show up.

---

### 3) Fireblast bonus spawns the wrong projectile type ID

In `bonus_apply`:

* **Original Fireblast (bonus id 8)** spawns **16 projectiles of type_id 9**.
* **Your code** spawns a ring using `type_id=8` (in `bonus_apply()`), which is incorrect for the original’s behavior.

This is a straight fidelity bug.

---

### 4) Some major bonuses are implemented as “timers only” (missing their real effects)

You’re already tracking the timers in `GameplayState.bonuses`, but several bonuses have **substantial behavior** in the original that isn’t yet modeled.

#### Freeze

In the original, Freeze is not “slow everything down” — it primarily changes *death/corpse behavior and visuals*:

* On pickup, it iterates the creature pool and **shatters/removes already-dead but still-active corpses**, spawning ice shards.
* While the timer is active, `creature_handle_death` does an alternate “ice shatter + remove creature” path and suppresses some blood effects.

In your port, Freeze currently sets a timer and otherwise does nothing equivalent.

#### Energizer

In the original (inside `creature_update_all`), Energizer:

* makes weaker creatures **flee** (heading flips away from player)
* and enables **“eat” kills** when the player is close enough (awards xp and calls death handling with guards)

In your port, Energizer currently sets a timer only; none of the AI/interaction behavior exists.

#### Nuke

In the original, Nuke is **not “kill everything everywhere”**:

* it spawns a shockwave-like effect (projectiles + explosion burst)
* triggers camera shake
* applies **radius damage** (~256 units) via a radius-damage helper using `creature_apply_damage` (damage_type 3)
* plays specific sounds

In your port, Nuke currently:

* sets all creature HP to 0 and clears projectiles (very different)

This one will noticeably change gameplay and score pacing.

---

### 5) Large parts of the perk set exist but have no gameplay effect yet

The perk selection machinery is strong, but a bunch of perks are currently “selectable but inert” because their behavioral hooks live in functions you haven’t ported yet (especially `creature_apply_damage` and `creature_update_all`).

A non-exhaustive list of perks that are *implemented as data / appear in quests* but currently have no meaningful runtime effect in core sim:

* **Lean Mean Exp Machine** (xp multiplier path missing; `award_experience()` only handles double-xp bonus)
* **Uranium Filled Bullets**, **Doctor**, **Barrel Greaser**, **Ion Gun Master**, **Pyromaniac** (damage scaling happens in the original’s `creature_apply_damage`)
* **Poison Bullets**, **Plaguebearer**, **Veins of Poison**, **Toxic Avenger** (status/infection logic is in original creature/projectile runtime; absent in your sim)
* **Radioactive** (original has proximity damage / interaction in creature update; not present)
* **Regeneration / Greater Regeneration** (no health-over-time logic visible in your runtime)
* **Unstoppable** (no corresponding “ignore X penalty / reaction” logic implemented)
* **Random Weapon / Mr Melee / Final Revenge / Highlander / Jinxed** (no clear runtime behavioral hook in `src/` today)

This is expected given your current “subset to unblock playable survival” notes, but it’s now the main gap between “playable” and “high-fidelity”.

---

### 6) Weapon firing paths are incomplete vs the documented projectile model

Your current `player_fire_weapon()` mostly assumes “weapon id == projectile type id” and spawns into either the main or secondary projectile pools.

But `docs/structs/projectile.md` documents **non-projectile weapon paths** in the original (handled via particles, not projectile_spawn), including:

* Plasma Rifle
* HR Flamer
* Mini-Rocket Swarmers
* Rainbow Gun

Those paths do not appear to be implemented as actual particle-based weapons in `player_fire_weapon()` today.

Also, you already note a known approximation:

* **Rocket Minigun**: comment says “native spawns multiple per shot; keep 1 for now”. That’s a fidelity gap you’ll want to close once the damage/death pipeline is corrected.

---

### 7) Frontend “meta” gaps are real but secondary to sim fidelity

These are already called out in `docs/rewrite/status.md`, and I agree with the priority:

* **Controls** screen is stubbed
* **Options** (especially keybinds / full parity) incomplete
* **Mods** screen stubbed
* **Statistics / detailed unlock progression** incomplete (notably stage-5 quest counters are explicitly “not modeled” in `src/crimson/game.py`)
* **SFX + transitions** missing in multiple views (game over path docs mention this)
* **Local multiplayer** is still effectively single-player throughout: even when player_count exists, kill attribution, perk application, HUD, and input are single-player assumptions.

---

## A detailed plan to finish the port with high fidelity

I’m going to lay this out in a dependency-aware order. The biggest theme: **fix event timing + canonical damage/death first**, because it unblocks “correct perks, bonuses, weapons” without hacks.

### Phase 1: Fix the obvious “wrong ID / wrong constant” bugs (fast, high ROI)

These are contained changes that won’t force architecture churn.

1. [x] **Fireblast type_id fix**

* File: `src/crimson/gameplay.py` (`bonus_apply`, `BonusId.FIREBLAST`)
* Change ring `type_id` from `8` → `9`
* Add the missing explosion sound hook (even if initially stubbed through your audio router)

2. [x] **Fix perk projectile burst type IDs**

* File: `src/crimson/gameplay.py`

  * `_perk_update_man_bomb()` → use `0x16`/`0x15` per original
  * `_perk_update_hot_tempered()` → use `0x0B`/`0x09`
  * Angry Reloader burst → use `0x0B`
* Add missing SFX triggers for each burst (original uses small explosion SFX)

3. [x] Add regression tests for these

* Create a “spawn signature” test that runs a controlled RNG seed and asserts:

  * the set of `(type_id, count)` spawned by each perk/bonus matches the expected list
  * (optional) that the angles are evenly spaced / match expected constants

This keeps you from re-breaking these while refactoring later.

---

### Phase 2: Port `creature_apply_damage` and make death side-effects immediate (core architecture fix)

This is the single most important phase for fidelity.

#### Goal

Make **every damage source** go through a single “canonical” implementation that matches `analysis/...creature_apply_damage` semantics, including immediate death handling.

#### Work items

1. [x] Implement `creature_apply_damage(...)` in `src/crimson/creatures/`

* New module suggestion: `src/crimson/creatures/damage.py`
* Signature should include:

  * `creature_id` / direct reference
  * `damage_amount`
  * `damage_type` (match original integers)
  * `impulse_vec` (x,y)
  * `owner_id` (for kill attribution)
* Must set:

  * `creature.hit_flash_timer = 0.2`
  * `creature.last_hit_owner_id = owner_id` (or “current player” mapping, matching original)
* Must apply perk-based damage scaling exactly where the original does it:

  * Uranium Filled Bullets (bullets)
  * Living Fortress (based on player timer(s))
  * Barrel Greaser / Doctor (bullets)
  * Ion Gun Master (damage_type 7)
  * Pyromaniac (damage_type 4)

2. [x] Implement / refactor `creature_handle_death(creature_id, keep_corpse)` to match original ordering

* You already have most “death plumbing” in `CreaturePool._start_death()`, but it’s currently triggered later and attributes xp to player 0.
* Bring it closer to the original behavior:

  * compute XP + multipliers
  * drop bonuses (respect `bonus_spawn_guard`)
  * apply Freeze shatter path when Freeze timer active
  * apply “corpse keep” flags and split-on-death logic
  * set active state and corpse timers correctly

3. [x] Update all damage call sites to use `creature_apply_damage`

* `ProjectilePool.update()`:

  * replace direct `creature.hp -= damage` with `creature_apply_damage(...)`
* Any radius/explosion logic:

  * ensure it uses the same entry point and sets `damage_type=3` where appropriate
* Any perk/bonus damage:

  * Nuke, Energizer “eat”, etc should call death/damage in the same way the original does

4. [x] Adjust the creature update loop to stop “starting death late”

* After this, `CreaturePool.update()` should **not** be responsible for initiating death side-effects.
* It *should* still be responsible for:

  * corpse movement / fading / hitbox shrink over time
  * removing fully expired corpses

A simple guard (similar to the original’s “hitbox_size != alive sentinel”) works well.

5. [x] Add a timing regression test

* Construct a test where:

  * a projectile hit reduces creature HP below 0
  * assert that XP/bonus drop happens **in the same frame** as the hit
  * not “one tick later”

This will catch the most important class of fidelity bugs.

---

### Phase 3: Implement bonus behaviors that depend on correct damage/death timing

Once Phase 2 is in, these become straightforward and correct.

1. [x] Freeze

- [x] On pickup: shatter/remove existing corpses.
- [x] On death while active: ice-shatter + remove creature (no corpse).
- [x] While active: freeze creature movement/AI/anim.
- [x] On render: freeze overlay quad pass (optional parity).

2. [x] Energizer

- [x] AI: invert heading away from player while active.
- [x] Suppress contact damage while active.
- [x] “Eat”: close-range kills via death handling (respect `bonus_spawn_guard`).

3. [x] Nuke

- [x] Spawn shockwave visuals + burst.
- [x] Ensure shockwave projectile speed uses weapon `projectile_meta`.
- [x] Apply radius damage around pickup origin.
- [x] Route damage via `creature_apply_damage` (`damage_type=3`).
- [x] Add correct SFX sequencing.

4. [x] Phase 3 tests

- [x] Nuke does *not* kill creatures outside radius in a contrived map layout.
- [x] Freeze shatters corpses immediately upon pickup.
- [x] Energizer causes flee + eat kills.

---

### Phase 4: Bring perks from “selectable” to “effective”

This is where fidelity jumps from “mostly works” to “feels like the original”.

Recommended workflow: **perk-by-perk audit + hook mapping**, not ad-hoc patching.

1. [x] Build a perk implementation matrix
   Create a doc (or a generated report) that maps each `PerkId` to:

* where it is applied in the original (player_update, creature_update_all, creature_apply_damage, projectile_update, bonus_update…)
* where it is implemented in your port (file/function)
* test coverage status
* output: `docs/rewrite/perk-matrix.md` (generated via `uv run python scripts/gen_perk_matrix.py`)

2. [x] Port perks in dependency order
   Start with perks that are implemented inside the functions you’re already refactoring:

**A. Damage pipeline perks** (in `creature_apply_damage`)

* [x] Uranium Filled Bullets
* [x] Doctor
* [x] Barrel Greaser
* [x] Living Fortress scaling
* [x] Ion Gun Master
* [x] Pyromaniac

**B. Survival/XP perks**

* [x] Lean Mean Exp Machine (passive XP tick)
* [x] Bloody Mess Quick Learner (death XP uses 1.3x multiplier)
* [x] Double XP bonus interactions (death XP doubled; perk ticks unaffected)

**C. Status / infection perks**
These typically require creature flags/timers:

* [x] Poison Bullets
  - [x] Gate self-damage flag to projectile hits (not bonus radius damage)
* [x] Plaguebearer
* [x] Veins of Poison
* [x] Toxic Avenger
* [x] Regression Bullets

**D. Player passive/tick perks**
These usually live in `player_update`:

* [x] Regeneration
* [x] Greater Regeneration (no runtime hook found; appears inert)
* [x] Pyrokinetic (aim-targeted particle burst)
* [x] Evil Eyes (freeze aimed creature)
* [x] Radioactive (proximity damage)
* [x] Unstoppable
* [x] Highlander
* [x] Jinxed (timer + random kill + accidents)

**E. Reload override perks**

* [x] Ammunition Within

**F. Perks without port refs**

* [x] Random Weapon
* [x] Mr. Melee
* [x] Final Revenge
* [x] Reflex Boosted

**G. Movement perks**

* [x] Long Distance Runner

**H. Accuracy / firing perks**

* [x] Sharpshooter

**I. Reload speed perks**

* [x] Fastloader

**J. Perk apply (one-shot) perks**

* [x] Fatal Lottery
* [x] Ammo Maniac
* [x] Grim Deal
* [x] Death Clock
* [x] Bandage
* [x] My Favourite Weapon

**K. Damage intake perks**

* [x] Tough Reloader

**L. Perk matrix “TBD” notes**

* [x] AntiPerk
* [x] Bloody Mess
* [x] Lean Mean Exp Machine
* [x] Instant Winner
* [x] Alternate Weapon
* [x] Fastshot
* [x] Anxious Loader
* [x] Telekinetic
* [x] Perk Expert
* [x] Unstoppable
* [x] Infernal Contract
* [x] Dodger
* [x] Bonus Magnet
* [x] Monster Vision
* [x] Hot Tempered
* [x] Bonus Economist
* [x] Thick Skinned
* [x] Regeneration
* [x] Ninja
* [x] Highlander
* [x] Perk Master
* [x] Breathing Room
* [x] Stationary Reloader
* [x] Lifeline 50-50

3. [x] Add minimal scenario tests per perk
   For each perk, add one tiny deterministic scenario:

* set perk active
* run N frames
* assert one or two key measurable outcomes (hp delta, xp delta, creature state, number of spawned effects)

This is how you keep “high fidelity” from regressing later.

---

### Phase 5: Weapon firing paths + projectile system completeness

Once damage/death/perks are correct, weapon work becomes much less painful because all the downstream semantics are unified.

1. [x] Implement the documented non-projectile weapon paths
   From `docs/structs/projectile.md`:

- [x] Plasma Rifle
- [x] HR Flamer
- [x] Mini-Rocket Swarmers
- [x] Rainbow Gun

These likely require:

- [x] a “particle weapon fire” path (spawn into particle pool)
- [x] correct hit checks/damage application for particles (which should call `creature_apply_damage`)

2. [x] Close the secondary projectile fidelity gaps

- [x] Rocket Minigun “multiple secondaries per shot”
- [x] Validate Seeker Rockets homing parameters vs decompile
- [x] Ensure Pulse Gun / Plasma Shotgun behaviors match (hit radius, damage pool behavior, on-hit effects)

3. Expand projectile type handling
   Right now, unhandled type IDs silently fall into generic behavior. That’s fine for subset play, but not for fidelity.

Action:

* enumerate projectile type IDs used by all weapons + perks + bonuses
* ensure each has:

  * correct speed/lifetime
  * hit radius
  * damage type
  * special behavior (splitter, shrinkifier, plague spreader, etc.)

4. Add “weapon fire signature” tests
   Similar to the perk burst tests:

* per weapon, under fixed seed, assert:

  * projectile count
  * type IDs
  * whether it used main vs secondary vs particle path
  * basic ammo consumption

---

### Phase 6: Meta-game + UI parity (after sim correctness)

This is a lot of work, but it’s mostly isolated from core sim once the core is correct.

1. [ ] Finish the missing screens

- [ ] Controls view (and keybind system)
- [ ] Options parity (audio/video/gameplay toggles that exist in the original)
- [ ] Mods view (even if it’s read-only / placeholder, wire the state machine correctly)

2. [ ] Statistics + progression

- [ ] Implement the “detailed stats” screen
- [ ] Resolve the “stage 5 quest progress counters not modeled” gap in `src/crimson/game.py` so saves match original expectations

3. [ ] Sound + transitions

- [ ] Add missing SFX hooks described in `docs/rewrite/game-over.md` and wherever else UI transitions diverge
- [ ] Resolve `docs/rewrite/survival-transition-fade.md` by adding runtime evidence and then matching the exact flags/alphas

---

### Phase 7: Multiplayer (if it’s in scope for fidelity)

You’ve already noted it as a major gap; it’s also the most invasive feature because it touches attribution, UI, input, and balance.

Do it after the single-player sim is correct.

Key items:

* Proper per-player `owner_id` behavior (including the friendlyfire toggle semantics; original uses `-100` in some cases)
* XP attribution based on `creature.last_hit_owner_id`
* Per-player HUD + perk selection
* Input mapping for 2–4 players (keyboard/controller), and mode rules that are player-count aware

---

## Suggested “golden oracle” strategy to keep fidelity high

You already have frida trace summaries for specific subsystems. To finish the remaining work without guesswork, expand that approach:

1. Create small scripted scenarios in the original exe (or with a save) that exercise:

* one perk at a time
* one bonus at a time
* one weapon at a time
* one creature AI behavior at a time

2. Frida-dump a compact per-frame log:

* player: hp/ammo/reload timers/selected weapon/spread heat/perk timers
* creature: pos/health/flags/last_hit_owner_id/hit_flash_timer
* projectile spawns: (type_id, owner_id, damage, pos, heading)
* bonus pickups: id + origin + resulting timers
* xp delta + level ups

3. In `src/`, build a deterministic harness that runs the same scenario and compares logs.

This avoids spending weeks “eyeballing feel”, and it’s the only realistic way to be confident when you refactor core functions like damage/death.

---

## The most important ordering constraint

If you do only one thing from this plan first:

**Port `creature_apply_damage` + immediate `creature_handle_death` semantics and route all damage through it.**

Everything else (Freeze, Energizer, Nuke correctness, perk damage scaling, proper weapon behavior, correct leveling timing) becomes significantly easier and cleaner once the event timing matches the original.

---

If you want, I can also produce a concrete “implementation checklist” file you can drop into `docs/rewrite/` (or issues) that enumerates each perk/bonus/weapon and links it to the decompiled function(s) and the target `src/` module to update — but the analysis above should already give you a clear, dependency-safe path forward.
