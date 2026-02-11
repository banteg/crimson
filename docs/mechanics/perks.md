---
tags:
  - mechanics
  - systems
  - perks
---

# Perks

Player-facing mechanics reference for perk behavior.

This page describes what perks do in gameplay terms (timers, multipliers,
limits, and interaction rules). It intentionally avoids decompile addresses,
source-file paths, and rewrite architecture details.

See also:

- [Perk ID map](../perk-id-map.md)
- [Perk runtime reference (static + parity notes)](../re/static/perks-runtime-reference.md)

## Conventions

- Numeric values are listed exactly when behavior is known.
- If two perks conflict, precedence is called out explicitly.
- Multiplayer notes are included only when behavior is shared/global.

## 0 — AntiPerk (`PerkId.ANTIPERK`)

### Effects

- Sentinel “no perk” entry; never offered to the player.

## 1 — Bloody Mess / Quick Learner (`PerkId.BLOODY_MESS_QUICK_LEARNER`)

### Effects

- **+30% XP from creature kills** (XP awarded at death).
- When blood/gore FX are enabled, projectile hits spawn **extra gore decals / blood particles**.
- The UI name/description toggles between “Bloody Mess” and “Quick Learner” based on the blood toggle.

## 2 — Sharpshooter (`PerkId.SHARPSHOOTER`)

### Effects

- **Tighter spread**: spread heat is forced to a low baseline (0.02).
- **Slightly slower firing**: shot cooldown is multiplied by **1.05**.
- Draws a **laser sight line** while active.

## 3 — Fastloader (`PerkId.FASTLOADER`)

### Effects

- **Reload time multiplier**: reload duration is multiplied by **0.7**.

## 4 — Lean Mean Exp. Machine (`PerkId.LEAN_MEAN_EXP_MACHINE`)

### Effects

- Passive XP drip: every **0.25s**, each player with the perk gains **`perk_count * 10` XP**.

## 5 — Long Distance Runner (`PerkId.LONG_DISTANCE_RUNNER`)

### Effects

- While moving, movement speed ramps normally up to **2.0**, then continues ramping to **2.8**.
- When not moving, speed decays quickly (`dt * 15`).

## 6 — Pyrokinetic (`PerkId.PYROKINETIC`)

### Effects

- While aiming close to a creature (within a small radius), periodically triggers a **heat/flare visual**:
  - every ~0.5s: spawns a small burst of particles with fixed intensities (0.8, 0.6, 0.4, 0.3, 0.2) and a random decal.

## 7 — Instant Winner (`PerkId.INSTANT_WINNER`)

### Effects

- Immediately grants **+2500 XP** to the picker.
- Stackable.

## 8 — Grim Deal (`PerkId.GRIM_DEAL`)

### Effects

- Immediately grants **+18% of current XP** (rounded down to int) to the picker.
- Immediately kills the picker (sets health negative).

## 9 — Alternate Weapon (`PerkId.ALTERNATE_WEAPON`)

### Effects

- Enables a **second weapon slot** (alternate weapon).
- **Movement speed penalty**: speed is multiplied by **0.8** while active.
- Reload input swaps primary and alternate weapon runtime state and adds **+0.1** to shot cooldown (to prevent instant swap-firing).

## 10 — Plaguebearer (`PerkId.PLAGUEBEARER`)

### Effects

- Enables the Plaguebearer system (treated as a global/shared flag in the original).
- While the infection counter is low enough:
  - Players infect nearby weak creatures (HP < 150) within **30** units, up to an infection-count cap.
  - Infected creatures take **15 damage every 0.5s**.
  - Infection spreads between nearby creatures (within **45** units) while the global infection count is below a cap.
- Each “infection kill” increments a global infection counter which gradually suppresses further spread/infection.

## 11 — Evil Eyes (`PerkId.EVIL_EYES`)

### Effects

- Picks a single creature near the aim point (within 12 units).
- That creature’s AI/movement is frozen while targeted.

## 12 — Ammo Maniac (`PerkId.AMMO_MANIAC`)

### Effects

- Increases clip size by **+25%**, rounded down, but at least **+1**:
  `clip += max(1, int(clip * 0.25))`.
- Applied on weapon assignment, so it persists across weapon swaps and reload refills.

## 13 — Radioactive (`PerkId.RADIOACTIVE`)

### Effects

- Creatures near the player are periodically damaged:
  - within 100 units, decrements a timer faster; when it wraps, deals damage proportional to proximity:
    `damage = (100 - dist) * 0.3` every **0.5s** per creature.
- Has a visible green “aura” around the player.
- Kills from the aura award XP directly and start the death staging without a full damage event path.

## 14 — Fastshot (`PerkId.FASTSHOT`)

### Effects

- **Faster firing**: shot cooldown is multiplied by **0.88**.

## 15 — Fatal Lottery (`PerkId.FATAL_LOTTERY`)

### Effects

- 50/50 outcome:
  - either immediately grants **+10000 XP**, or
  - immediately kills the picker.
- Stackable.

## 16 — Random Weapon (`PerkId.RANDOM_WEAPON`)

### Effects

- Quest-only perk that immediately assigns a random available weapon:
  - retries up to ~100 times,
  - avoids the pistol and the currently equipped weapon.
- Stackable.

## 17 — Mr. Melee (`PerkId.MR_MELEE`)

### Effects

- When a creature lands a melee “contact damage” tick on the player:
  - the player automatically counter-hits the attacker for **25 damage** (damage type 2),
  - **and the player still takes the contact damage** for that tick.

## 18 — Anxious Loader (`PerkId.ANXIOUS_LOADER`)

### Effects

- While reloading (`reload_timer > 0`), each “fire” press reduces reload timer by **0.05** seconds.

## 19 — Final Revenge (`PerkId.FINAL_REVENGE`)

### Effects

- When the player dies, triggers an explosion centered on the player:
  - radius **512**
  - damage falloff: `damage = (512 - dist) * 5.0`
- Plays large explosion + shockwave SFX.
- Uses a “bonus spawn guard” style toggle during the effect in the original (to match stats/spawn semantics).

## 20 — Telekinetic (`PerkId.TELEKINETIC`)

### Effects

- Allows remote pickup of bonuses:
  - aim at a bonus within **24** units,
  - maintain aim hover for **>650ms**,
  - bonus is picked up automatically.

## 21 — Perk Expert (`PerkId.PERK_EXPERT`)

### Effects

- Perk selection offers **6 choices** instead of 5.
- UI layout is adjusted for the extra entry and shows an “extra perk sponsored…” line.

## 22 — Unstoppable (`PerkId.UNSTOPPABLE`)

### Effects

- On taking damage, suppresses the normal “hit disruption”:
  - no random heading knock,
  - no spread heat penalty.
- Damage still applies normally.

## 23 — Regression Bullets (`PerkId.REGRESSION_BULLETS`)

### Effects

- While reloading (`reload_timer != 0`), firing is allowed if the player has **XP > 0**:
  - consumes XP based on weapon reload time and ammo class:
    - `cost = reload_time * 4.0` when `weapon_ammo_class == 1`
    - `cost = reload_time * 200.0` otherwise
  - XP is clamped to be non-negative.
  - the shot fires **without consuming ammo**.
- Reload cannot be “restarted” while already reloading when this perk (or Ammunition Within) is active (prevents reload-reset abuse).

## 24 — Infernal Contract (`PerkId.INFERNAL_CONTRACT`)

### Effects

- Immediately:
  - sets every alive player to **0.1 health**,
  - grants the picker **+3 levels** and **+3 pending perk picks**.
- Not offered while Death Clock is active.

## 25 — Poison Bullets (`PerkId.POISON_BULLETS`)

### Effects

- On projectile hit to a creature: 1/8 chance to poison (`(rand & 7) == 1`).
- Poisoned creatures take self-damage every frame:
  - weak poison: `dt * 60`
  - strong poison (when Toxic Avenger sets the strong bit): `dt * 180`
- Poison is applied via the “normal damage” path (hit flash / heading jitter side-effects occur).
- Poisoned creatures render a **red aura** (60×60, effect atlas `0x10`) behind them with corpse-fade alpha.

## 26 — Dodger (`PerkId.DODGER`)

### Effects

- When taking damage, 1/5 chance to dodge completely (no damage).
- Ninja (if owned) overrides Dodger (checked first).

## 27 — Bonus Magnet (`PerkId.BONUS_MAGNET`)

### Effects

- Adds an extra chance for a bonus to spawn on kill when the base roll fails.
- Interacts with pistol special-case rules (pistol already has its own bonus-boost rules).

## 28 — Uranium Filled Bullets (`PerkId.URANIUM_FILLED_BULLETS`)

### Effects

- Bullet damage is doubled (**×2.0**) when the attacker has the perk.

## 29 — Doctor (`PerkId.DOCTOR`)

### Effects

- Bullet damage bonus: **×1.2** when the attacker has the perk.
- Shows a target health bar for the creature near the aim point (same target selection as Pyrokinetic/Evil Eyes).
  - Corpses that are still “active/targetable” render as **0%**.

## 30 — Monster Vision (`PerkId.MONSTER_VISION`)

### Effects

- Not offered when FX detail is disabled (config gating).
- Renders a highlight behind each active creature:
  - yellow 90×90 quad (effect atlas `0x10`),
  - fades during corpse despawn.
- Disables the creature shadow pass while active.

## 31 — Hot Tempered (`PerkId.HOT_TEMPERED`)

### Effects

- Periodically spawns an 8-shot ring centered on the player:
  - even indices: Plasma Minigun projectile
  - odd indices: Plasma Rifle projectile
  - angles: `idx * (pi/4)`
- Interval is randomized to **`(rand % 8) + 2` seconds** after each burst.
- Projectile owner id depends on friendly-fire setting:
  - friendly fire off: `owner_id = -100`
  - friendly fire on: `owner_id = -1 - player_index`

## 32 — Bonus Economist (`PerkId.BONUS_ECONOMIST`)

### Effects

- Timed bonuses last **50% longer** (timer increments are multiplied by 1.5).

## 33 — Thick Skinned (`PerkId.THICK_SKINNED`)

### Effects

- On pick: reduces current health to **2/3** (clamped to at least 1.0).
- On damage taken: damage is multiplied by **2/3** (applied before dodge logic).
- Not offered while Death Clock is active.

## 34 — Barrel Greaser (`PerkId.BARREL_GREASER`)

### Effects

- Bullet damage multiplier: **×1.4**.
- Player-owned projectiles step more aggressively (doubling movement steps), making bullets effectively “faster” and harder to dodge.

## 35 — Ammunition Within (`PerkId.AMMUNITION_WITHIN`)

### Effects

- While reloading (`reload_timer != 0`), firing is allowed if **XP > 0**:
  - the shot fires without consuming ammo,
  - the player takes self-damage per shot:
    - fire ammo class (`weapon_ammo_class == 1`): **0.15**
    - otherwise: **1.0**
  - self-damage is applied via `player_take_damage` (so Thick Skinned / Dodger / Ninja interactions apply).
- Regression Bullets takes precedence if both perks are active.
- Reload restart is blocked while already reloading (shared guard with Regression Bullets).

## 36 — Veins of Poison (`PerkId.VEINS_OF_POISON`)

### Effects

- When a creature lands a melee contact-damage tick on the player (and the player isn’t shielded):
  - the attacking creature is poisoned (weak poison tick).
- Hardcore quest gating may suppress poison perks in a specific stage.

## 37 — Toxic Avenger (`PerkId.TOXIC_AVENGER`)

### Effects

- Like Veins of Poison, but applies **strong poison** (fast tick) to attackers on contact when not shielded.
- Requires Veins of Poison.

## 38 — Regeneration (`PerkId.REGENERATION`)

### Effects

- Each frame (when a random bit hits), heals each alive player by **+dt**, clamped to 100:
  - triggers only if `0 < health < 100`
  - random gate: `(rand & 1) != 0`

## 39 — Pyromaniac (`PerkId.PYROMANIAC`)

### Effects

- Fire damage multiplier: **×1.5** when the attacker has the perk.
- Consumes one RNG call as a side-effect in the original.
- Typically offered only when the current weapon is Flamethrower (selection gating).

## 40 — Ninja (`PerkId.NINJA`)

### Effects

- When taking damage, 1/3 chance to dodge completely (`rand % 3 == 0`).
- Takes precedence over Dodger.

## 41 — Highlander (`PerkId.HIGHLANDER`)

### Effects

- Incoming damage does not reduce health.
- Instead, each time a hit lands, there is a **10% chance** to die instantly (`rand % 10 == 0`).
- Normal “on-hit disruption” still applies unless Unstoppable is active.

## 42 — Jinxed (`PerkId.JINXED`)

### Effects

- Periodically:
  - has a 1/10 chance to deal **5 self-damage** (and emit two random decals),
  - and, if Freeze bonus is not active, may instantly kill a random creature and award its XP (no normal death handler).
- Uses a global timer that is randomized after each activation.

## 43 — Perk Master (`PerkId.PERK_MASTER`)

### Effects

- Perk selection offers **7 choices** instead of 5 (and instead of 6 with Perk Expert).

## 44 — Reflex Boosted (`PerkId.REFLEX_BOOSTED`)

### Effects

- Global slow-motion effect: scales frame dt by **0.9** while active (i.e., the world runs ~10% slower).

## 45 — Greater Regeneration (`PerkId.GREATER_REGENERATION`)

### Effects

- In this build, **no runtime effect** has been found (it appears to be a no-op perk).
- Death Clock clears its perk count on apply.

## 46 — Breathing Room (`PerkId.BREATHING_ROOM`)

### Effects

- Two-player-only perk.
- On pick:
  - reduces each alive player’s health to **1/3** (subtracts 2/3),
  - forces every active creature into the “death staging” path without awarding XP,
  - clears `bonus_spawn_guard`.

## 47 — Death Clock (`PerkId.DEATH_CLOCK`)

### Effects

- On pick:
  - clears Regeneration and Greater Regeneration perk counts,
  - sets each alive player’s health to **100**.
- While active:
  - immune to all other damage,
  - health drains at a fixed rate: **100 HP over 30 seconds** (`health -= dt * 3.3333333`),
  - medikits are removed from the random bonus pool,
  - perk selection blocks a set of perks that would undermine the clock (regen, thick skinned, etc).

## 48 — My Favourite Weapon (`PerkId.MY_FAVOURITE_WEAPON`)

### Effects

- Increases clip size by **+2** (applied on pick and on weapon assignment).
- Weapon bonuses cannot spawn or be selected; picking up a weapon bonus is ignored.

## 49 — Bandage (`PerkId.BANDAGE`)

### Effects

- Randomly multiplies current health by **1..50**, then clamps to **100**.
- Spawns an 8-particle burst effect.

## 50 — Angry Reloader (`PerkId.ANGRY_RELOADER`)

### Effects

- During a reload, when the reload timer crosses the half threshold (from >50% to ≤50%) and `reload_timer_max > 0.5`:
  - spawns a projectile ring centered on the player:
    - projectile type: Plasma Minigun
    - count: `7 + int(reload_timer_max * 4.0)`
    - angle offset: `0.1`
  - plays `sfx_explosion_small`
- Uses Stationary Reloader’s 3× reload scaling when stationary.
- Projectile owner id depends on friendly-fire setting (`-100` when off, else `-1-player_index`).

## 51 — Ion Gun Master (`PerkId.ION_GUN_MASTER`)

### Effects

- Ion blast damage multiplier: **×1.2**.
- Ion AoE radii are scaled by **×1.2** for ion weapons.
- The damage multiplier is global (not attacker-bound): any `damage_type == 7` damage is scaled while Ion Gun Master exists.

## 52 — Stationary Reloader (`PerkId.STATIONARY_RELOADER`)

### Effects

- While stationary, reload speed is multiplied by **3.0**.

## 53 — Man Bomb (`PerkId.MAN_BOMB`)

### Effects

- Charges while stationary; when the timer exceeds an interval (starts at 4.0s):
  - spawns 8 ion projectiles in a ring with per-projectile angular jitter:
    - even indices: Ion Minigun
    - odd indices: Ion Rifle
    - angle: `idx*(pi/4) + ((rand%50)*0.01 - 0.25)`
  - plays `sfx_explosion_small`
  - subtracts the interval from the timer and resets the interval back to 4.0.
- If the player moves, the timer is reset to 0.0 (so it only accumulates while stationary).
- Projectile owner id depends on friendly-fire setting (`-100` when off, else `-1-player_index`).

## 54 — Fire Caugh (`PerkId.FIRE_CAUGH`)

### Effects

- Periodically (interval randomized to 2–5 seconds):
  - plays two weapon-fire SFX,
  - spawns one Fire Bullets projectile from the muzzle:
    - muzzle is offset by a fixed `-0.150915` rad rotation (same muzzle convention as normal firing),
    - aim is jittered using the same distance-scaled spread model as normal firing (`dist * spread_heat`),
  - spawns a small grey sprite FX traveling forward from the muzzle.
- Projectile owner id depends on friendly-fire setting (`-100` when off, else `-1-player_index`).

## 55 — Living Fortress (`PerkId.LIVING_FORTRESS`)

### Effects

- While stationary, a timer ramps up to **30s**.
- Bullet damage scaling: for each alive player, bullet damage is multiplied by:
  `living_fortress_timer * 0.05 + 1.0`
  (with multiple alive players, the multiplier applies once per player).

## 56 — Tough Reloader (`PerkId.TOUGH_RELOADER`)

### Effects

- While reloading (`reload_active != 0`), incoming damage is multiplied by **0.5**.

## 57 — Lifeline 50-50 (`PerkId.LIFELINE_50_50`)

### Effects

- On pick, iterates the creature pool in slot order and removes roughly half of eligible creatures:
  - a toggle flips each slot; when “on”, and the creature is:
    - active,
    - `hp <= 500`,
    - `(flags & 4) == 0`,
    it is removed immediately (no normal death handling / no XP).
  - spawns a small burst FX per removed creature (4 particles).
