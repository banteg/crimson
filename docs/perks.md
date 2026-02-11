---
tags:
  - gameplay
  - perks
---

# Perks (behavior reference)

This page documents the **actual runtime behavior** of each perk in:

- **Original**: Crimsonland v1.9.93 (`analysis/ghidra/raw/crimsonland.exe_decompiled.c`)
- **Rewrite**: our Python port (`src/`)

For player-facing shared mechanics prose, see [Perks mechanics (version-agnostic)](perks-mechanics.md).
For ID ↔ name mapping, see [Perk ID map](perk-id-map.md). For a quick “where is this wired” view in the rewrite, see [perk matrix](rewrite/perk-matrix.md).

Notes:

- Many perk effects are implemented by a small set of hot paths in the original:
  `perk_apply` (0x004055e0), `perks_update_effects` (0x00406b40), `player_update` (0x004136b0),
  `player_fire_weapon` (0x00444980), `player_take_damage` (0x00425e50),
  `creature_update_all` (0x00426220), `creature_apply_damage` (0x004207c0),
  `projectile_update` (0x00420b90), and rendering passes.
- In the rewrite, perk counts live on `PlayerState.perk_counts` and are typically treated as shared state across players (synced from player 0).

## 0 — AntiPerk (`PerkId.ANTIPERK`)

### Effects

- Sentinel “no perk” entry; never offered to the player.

### Original

- `perk_can_offer` (0x0042fb10): explicitly rejects `perk_id_antiperk`.

### Rewrite

- `src/crimson/gameplay.py`: `perk_can_offer()` rejects `PerkId.ANTIPERK`.

## 1 — Bloody Mess / Quick Learner (`PerkId.BLOODY_MESS_QUICK_LEARNER`)

### Effects

- **+30% XP from creature kills** (XP awarded at death).
- When blood/gore FX are enabled, projectile hits spawn **extra gore decals / blood particles**.
- The UI name/description toggles between “Bloody Mess” and “Quick Learner” based on the blood toggle.

### Original

- Kill XP: creature death handling (via `creature_update_all` → `creature_handle_death` path).
- Hit FX: projectile hit handling queues extra decals / blood splatter when the perk is active and blood is enabled.

### Rewrite

- XP multiplier on kill: `src/crimson/creatures/runtime.py`: `CreaturePool._start_death()`.
- Extra hit decals/blood: `src/crimson/game_world.py`: `GameWorld._queue_projectile_decals()`.
- Name/description toggle: `src/crimson/perks/ids.py`: `perk_display_name()` / `perk_display_description()`.

## 2 — Sharpshooter (`PerkId.SHARPSHOOTER`)

### Effects

- **Tighter spread**: spread heat is forced to a low baseline (0.02).
- **Slightly slower firing**: shot cooldown is multiplied by **1.05**.
- Draws a **laser sight line** while active.

### Original

- `player_update` (0x004136b0): forces `spread_heat = 0.02` while active.
- `player_fire_weapon` (0x00444980): applies `shot_cooldown *= 1.05` and avoids the normal post-shot spread heat increase.
- Rendering: draws the laser overlay in the player render path.

### Rewrite

- Shot cooldown and spread behavior: `src/crimson/gameplay.py`: `player_fire_weapon()`, `player_update()`.
- Laser rendering: `src/crimson/render/world_renderer.py`: `_draw_sharpshooter_laser_sight()`.

## 3 — Fastloader (`PerkId.FASTLOADER`)

### Effects

- **Reload time multiplier**: reload duration is multiplied by **0.7**.

### Original

- `player_start_reload` (0x00413430): applies the multiplier when starting a reload.

### Rewrite

- `src/crimson/gameplay.py`: `player_start_reload()`.

## 4 — Lean Mean Exp. Machine (`PerkId.LEAN_MEAN_EXP_MACHINE`)

### Effects

- Passive XP drip: every **0.25s**, each player with the perk gains **`perk_count * 10` XP**.

### Original

- `perks_update_effects` (0x00406b40): timer-based periodic XP grant.

### Rewrite

- `src/crimson/gameplay.py`: `perks_update_effects()` (Lean Mean timer step).

## 5 — Long Distance Runner (`PerkId.LONG_DISTANCE_RUNNER`)

### Effects

- While moving, movement speed ramps normally up to **2.0**, then continues ramping to **2.8**.
- When not moving, speed decays quickly (`dt * 15`).

### Original

- `player_update` (0x004136b0): move-speed ramp/decay logic with perk-enabled extension to 2.8.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

## 6 — Pyrokinetic (`PerkId.PYROKINETIC`)

### Effects

- While aiming close to a creature (within a small radius), periodically triggers a **heat/flare visual**:
  - every ~0.5s: spawns a small burst of particles with fixed intensities (0.8, 0.6, 0.4, 0.3, 0.2) and a random decal.

### Original

- `perks_update_effects` (0x00406b40): selects an aim target via `creature_find_in_radius(..., 12.0, 0)` and runs the timer/FX emission.

### Rewrite

- `src/crimson/gameplay.py`: `perks_update_effects()` (Pyrokinetic step).

## 7 — Instant Winner (`PerkId.INSTANT_WINNER`)

### Effects

- Immediately grants **+2500 XP** to the picker.
- Stackable.

### Original

- `perk_apply` (0x004055e0): adds 2500 XP.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Instant Winner handler).

## 8 — Grim Deal (`PerkId.GRIM_DEAL`)

### Effects

- Immediately grants **+18% of current XP** (rounded down to int) to the picker.
- Immediately kills the picker (sets health negative).

### Original

- `perk_apply` (0x004055e0): `experience += int(experience * 0.18)` then `health = -1.0`.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Grim Deal handler).

## 9 — Alternate Weapon (`PerkId.ALTERNATE_WEAPON`)

### Effects

- Enables a **second weapon slot** (alternate weapon).
- **Movement speed penalty**: speed is multiplied by **0.8** while active.
- Reload input swaps primary and alternate weapon runtime state and adds **+0.1** to shot cooldown (to prevent instant swap-firing).

### Original

- `player_apply_move_with_spawn_avoidance` (0x0041e290): movement scaling.
- `player_update` (0x004136b0): reload-triggered swap behavior + shot cooldown bump.

### Rewrite

- Swap and carry behavior: `src/crimson/gameplay.py`: `player_swap_alt_weapon()`, `player_update()`, `bonus_apply()`.

## 10 — Plaguebearer (`PerkId.PLAGUEBEARER`)

### Effects

- Enables the Plaguebearer system (treated as a global/shared flag in the original).
- While the infection counter is low enough:
  - Players infect nearby weak creatures (HP < 150) within **30** units, up to an infection-count cap.
  - Infected creatures take **15 damage every 0.5s**.
  - Infection spreads between nearby creatures (within **45** units) while the global infection count is below a cap.
- Each “infection kill” increments a global infection counter which gradually suppresses further spread/infection.

### Original

- `perk_apply` (0x004055e0): sets `player_plaguebearer_active` (global-ish field on player0).
- `creature_update_all` (0x00426220): infection flagging, ticking, spread (`plaguebearer_spread_infection`), and infection kill bookkeeping.

### Rewrite

- Flag application: `src/crimson/gameplay.py`: `perk_apply()` (Plaguebearer handler sets `plaguebearer_active` for all players).
- Creature-side behavior: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (contact infection, tick damage, spread).

## 11 — Evil Eyes (`PerkId.EVIL_EYES`)

### Effects

- Picks a single creature near the aim point (within 12 units).
- That creature’s AI/movement is frozen while targeted.

### Original

- `perks_update_effects` (0x00406b40): updates `evil_eyes_target_creature` via `creature_find_in_radius`.
- `creature_update_all` (0x00426220): skips AI update for the targeted creature.

### Rewrite

- Target selection: `src/crimson/gameplay.py`: `perks_update_effects()` (Evil Eyes target step).
- Freeze behavior: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (evil-eyes target handling).

## 12 — Ammo Maniac (`PerkId.AMMO_MANIAC`)

### Effects

- Increases clip size by **+25%**, rounded down, but at least **+1**:
  `clip += max(1, int(clip * 0.25))`.
- Applied on weapon assignment, so it persists across weapon swaps and reload refills.

### Original

- `perk_apply` (0x004055e0): reassigns each player’s current weapon to force clip recalculation.
- `weapon_assign_player` (0x00452d40): applies the clip-size modifier.

### Rewrite

- Clip sizing: `src/crimson/gameplay.py`: `weapon_assign_player()` (Ammo Maniac modifier).
- Apply-time reassignment: `src/crimson/gameplay.py`: `perk_apply()` (Ammo Maniac handler).

## 13 — Radioactive (`PerkId.RADIOACTIVE`)

### Effects

- Creatures near the player are periodically damaged:
  - within 100 units, decrements a timer faster; when it wraps, deals damage proportional to proximity:
    `damage = (100 - dist) * 0.3` every **0.5s** per creature.
- Has a visible green “aura” around the player.
- Kills from the aura award XP directly and start the death staging without a full damage event path.

### Original

- `creature_update_all` (0x00426220): proximity check, timer wrap, falloff damage; special-case kill/XP handling.
- Rendering: draws the player aura (effect atlas id `0x10`).

### Rewrite

- Gameplay: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (Radioactive tick and kill handling).
- Rendering: `src/crimson/render/world_renderer.py`: player aura in `_draw_player_trooper_sprite()`.

## 14 — Fastshot (`PerkId.FASTSHOT`)

### Effects

- **Faster firing**: shot cooldown is multiplied by **0.88**.

### Original

- `player_fire_weapon` (0x00444980): applies the cooldown multiplier.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()`.

## 15 — Fatal Lottery (`PerkId.FATAL_LOTTERY`)

### Effects

- 50/50 outcome:
  - either immediately grants **+10000 XP**, or
  - immediately kills the picker.
- Stackable.

### Original

- `perk_apply` (0x004055e0): `(crt_rand() & 1)` decides XP vs death.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Fatal Lottery handler).

## 16 — Random Weapon (`PerkId.RANDOM_WEAPON`)

### Effects

- Quest-only perk that immediately assigns a random available weapon:
  - retries up to ~100 times,
  - avoids the pistol and the currently equipped weapon.
- Stackable.

### Original

- `perk_apply` (0x004055e0): random selection and `weapon_assign_player`.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Random Weapon handler).

## 17 — Mr. Melee (`PerkId.MR_MELEE`)

### Effects

- When a creature lands a melee “contact damage” tick on the player:
  - the player automatically counter-hits the attacker for **25 damage** (damage type 2),
  - **and the player still takes the contact damage** for that tick.

### Original

- `creature_update_all` (0x00426220): on contact-damage tick, calls `creature_apply_damage(attacker, 25, damage_type=2, impulse=(0,0))` when Mr. Melee is active, without suppressing the player damage path.

### Rewrite

- `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()` (Mr. Melee branch + deferred death handling).

## 18 — Anxious Loader (`PerkId.ANXIOUS_LOADER`)

### Effects

- While reloading (`reload_timer > 0`), each “fire” press reduces reload timer by **0.05** seconds.

### Original

- `player_update` (0x004136b0): checks `input_primary_just_pressed()` and applies the timer reduction.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

## 19 — Final Revenge (`PerkId.FINAL_REVENGE`)

### Effects

- When the player dies, triggers an explosion centered on the player:
  - radius **512**
  - damage falloff: `damage = (512 - dist) * 5.0`
- Plays large explosion + shockwave SFX.
- Uses a “bonus spawn guard” style toggle during the effect in the original (to match stats/spawn semantics).

### Original

- `player_take_damage` (0x00425e50): death check triggers the revenge burst and radial damage via `creature_apply_damage` (damage type 3).

### Rewrite

- `src/crimson/sim/world_state.py`: death pipeline triggers the revenge burst and applies damage.

## 20 — Telekinetic (`PerkId.TELEKINETIC`)

### Effects

- Allows remote pickup of bonuses:
  - aim at a bonus within **24** units,
  - maintain aim hover for **>650ms**,
  - bonus is picked up automatically.

### Original

- Bonus update logic uses a per-player aim-hover timer and a fixed delay threshold.

### Rewrite

- `src/crimson/gameplay.py`: `bonus_telekinetic_update()`, `bonus_find_aim_hover_entry()`.

## 21 — Perk Expert (`PerkId.PERK_EXPERT`)

### Effects

- Perk selection offers **6 choices** instead of 5.
- UI layout is adjusted for the extra entry and shows an “extra perk sponsored…” line.

### Original

- Perk selection UI logic adjusts choice count and layout while the perk is active.

### Rewrite

- Choice count: `src/crimson/gameplay.py`: `perk_choice_count()`.
- UI layout + sponsor text: `src/crimson/ui/perk_menu.py`, `src/crimson/views/perks.py`.

## 22 — Unstoppable (`PerkId.UNSTOPPABLE`)

### Effects

- On taking damage, suppresses the normal “hit disruption”:
  - no random heading knock,
  - no spread heat penalty.
- Damage still applies normally.

### Original

- `player_take_damage` (0x00425e50): gates the disruption logic on perk presence.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 23 — Regression Bullets (`PerkId.REGRESSION_BULLETS`)

### Effects

- While reloading (`reload_timer != 0`), firing is allowed if the player has **XP > 0**:
  - consumes XP based on weapon reload time and ammo class:
    - `cost = reload_time * 4.0` when `weapon_ammo_class == 1`
    - `cost = reload_time * 200.0` otherwise
  - XP is clamped to be non-negative.
  - the shot fires **without consuming ammo**.
- Reload cannot be “restarted” while already reloading when this perk (or Ammunition Within) is active (prevents reload-reset abuse).

### Original

- `player_fire_weapon` (0x00444980): implements the “fire during reload by paying XP” path.
- `player_start_reload` (0x00413430): reload restart guard when Regression Bullets or Ammunition Within is active.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()` (reload firing + XP drain), `player_start_reload()` (restart guard).

## 24 — Infernal Contract (`PerkId.INFERNAL_CONTRACT`)

### Effects

- Immediately:
  - sets every alive player to **0.1 health**,
  - grants the picker **+3 levels** and **+3 pending perk picks**.
- Not offered while Death Clock is active.

### Original

- `perk_apply` (0x004055e0): applies the health reduction and perk/level grants.
- Perk offering logic blocks the perk under Death Clock.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Infernal Contract handler) and perk generation (`perk_generate_choices()`).

## 25 — Poison Bullets (`PerkId.POISON_BULLETS`)

### Effects

- On projectile hit to a creature: 1/8 chance to poison (`(rand & 7) == 1`).
- Poisoned creatures take self-damage every frame:
  - weak poison: `dt * 60`
  - strong poison (when Toxic Avenger sets the strong bit): `dt * 180`
- Poison is applied via the “normal damage” path (hit flash / heading jitter side-effects occur).
- Poisoned creatures render a **red aura** (60×60, effect atlas `0x10`) behind them with corpse-fade alpha.

### Original

- `projectile_update` (0x00420b90): sets poison flags on hit.
- `creature_update_all` (0x00426220): applies self-damage using `creature_apply_damage(..., damage_type=0, impulse=(0,0))`.
- Rendering: creature overlay draws aura `0x10` when poison flag is set.

### Rewrite

- Poison flagging: `src/crimson/projectiles.py`: `ProjectilePool.update()` hit logic.
- Poison tick: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` routes self-damage through `creature_apply_damage()`.
- Aura render: `src/crimson/render/world_renderer.py`: creature overlay in `WorldRenderer.draw()`.

## 26 — Dodger (`PerkId.DODGER`)

### Effects

- When taking damage, 1/5 chance to dodge completely (no damage).
- Ninja (if owned) overrides Dodger (checked first).

### Original

- `player_take_damage` (0x00425e50): Dodger is `crt_rand() % 5 == 0` if Ninja is not active.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 27 — Bonus Magnet (`PerkId.BONUS_MAGNET`)

### Effects

- Adds an extra chance for a bonus to spawn on kill when the base roll fails.
- Interacts with pistol special-case rules (pistol already has its own bonus-boost rules).

### Original

- Bonus spawn-on-kill logic (`bonus_try_spawn_on_kill`): additional roll gates on perk.

### Rewrite

- `src/crimson/gameplay.py`: `BonusPool.try_spawn_on_kill()`.

## 28 — Uranium Filled Bullets (`PerkId.URANIUM_FILLED_BULLETS`)

### Effects

- Bullet damage is doubled (**×2.0**) when the attacker has the perk.

### Original

- `creature_apply_damage` (0x004207c0): when `damage_type == 1`, doubles damage.

### Rewrite

- `src/crimson/creatures/damage.py`: `creature_apply_damage()`.

## 29 — Doctor (`PerkId.DOCTOR`)

### Effects

- Bullet damage bonus: **×1.2** when the attacker has the perk.
- Shows a target health bar for the creature near the aim point (same target selection as Pyrokinetic/Evil Eyes).
  - Corpses that are still “active/targetable” render as **0%**.

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- Target selection: uses `creature_find_in_radius(aim, 12.0, 0)`.
- HUD draw: draws a 64px bar with the clamped `health/max_health` ratio.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- UI: `src/crimson/modes/base_gameplay_mode.py`: `_draw_target_health_bar()`, and `src/crimson/ui/hud.py`: `draw_target_health_bar()`.

## 30 — Monster Vision (`PerkId.MONSTER_VISION`)

### Effects

- Not offered when FX detail is disabled (config gating).
- Renders a highlight behind each active creature:
  - yellow 90×90 quad (effect atlas `0x10`),
  - fades during corpse despawn.
- Disables the creature shadow pass while active.

### Original

- Offer gating: perk selection checks FX detail.
- Rendering: creature render pass draws `0x10` behind creatures; shadow pass is disabled while active.

### Rewrite

- Offer gating: `src/crimson/gameplay.py`: `perk_can_offer()` / perk selection.
- Rendering: `src/crimson/render/world_renderer.py`: `WorldRenderer.draw()` (Monster Vision overlay and shadow gating).

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

### Original

- `player_update` (0x004136b0): timer logic + randomized interval + ring spawn.

### Rewrite

- `src/crimson/gameplay.py`: `_perk_update_hot_tempered()` (called from `player_update()`).

## 32 — Bonus Economist (`PerkId.BONUS_ECONOMIST`)

### Effects

- Timed bonuses last **50% longer** (timer increments are multiplied by 1.5).

### Original

- Bonus application scales duration increments while the perk is active.

### Rewrite

- `src/crimson/gameplay.py`: `bonus_apply()` (economist multiplier).

## 33 — Thick Skinned (`PerkId.THICK_SKINNED`)

### Effects

- On pick: reduces current health to **2/3** (clamped to at least 1.0).
- On damage taken: damage is multiplied by **2/3** (applied before dodge logic).
- Not offered while Death Clock is active.

### Original

- `perk_apply` (0x004055e0): health scaling on pick.
- `player_take_damage` (0x00425e50): damage scaling.
- Perk offering blocks it under Death Clock.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()`.
- `src/crimson/player_damage.py`: `player_take_damage()`.
- Offer gating: `src/crimson/gameplay.py`: perk generation.

## 34 — Barrel Greaser (`PerkId.BARREL_GREASER`)

### Effects

- Bullet damage multiplier: **×1.4**.
- Player-owned projectiles step more aggressively (doubling movement steps), making bullets effectively “faster” and harder to dodge.

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- `projectile_update` (0x00420b90): doubles the movement step count when the perk is active and the projectile is player-owned.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- Projectile stepping: `src/crimson/projectiles.py`: `ProjectilePool.update()`.

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

### Original

- `player_fire_weapon` (0x00444980): implements the “fire during reload by paying health” path.
- `player_start_reload` (0x00413430): restart guard.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()` and `player_start_reload()`.

## 36 — Veins of Poison (`PerkId.VEINS_OF_POISON`)

### Effects

- When a creature lands a melee contact-damage tick on the player (and the player isn’t shielded):
  - the attacking creature is poisoned (weak poison tick).
- Hardcore quest gating may suppress poison perks in a specific stage.

### Original

- `creature_update_all` (0x00426220): on contact-damage, checks `shield_timer` and sets poison flags.
- Perk offering: hardcore quest gating.

### Rewrite

- Contact poison flagging: `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()`.
- Offer gating: `src/crimson/gameplay.py`: `perk_can_offer()`.

## 37 — Toxic Avenger (`PerkId.TOXIC_AVENGER`)

### Effects

- Like Veins of Poison, but applies **strong poison** (fast tick) to attackers on contact when not shielded.
- Requires Veins of Poison.

### Original

- `creature_update_all` (0x00426220): sets both weak+strong poison flags.

### Rewrite

- `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()`.

## 38 — Regeneration (`PerkId.REGENERATION`)

### Effects

- Each frame (when a random bit hits), heals each alive player by **+dt**, clamped to 100:
  - triggers only if `0 < health < 100`
  - random gate: `(rand & 1) != 0`

### Original

- `perks_update_effects` (0x00406b40): heal loop.

### Rewrite

- `src/crimson/gameplay.py`: `perks_update_effects()` (Regeneration step).

## 39 — Pyromaniac (`PerkId.PYROMANIAC`)

### Effects

- Fire damage multiplier: **×1.5** when the attacker has the perk.
- Consumes one RNG call as a side-effect in the original.
- Typically offered only when the current weapon is Flamethrower (selection gating).

### Original

- `creature_apply_damage` (0x004207c0): fire damage scaling and a `crt_rand()` side-effect.
- Perk offering logic gates by current weapon.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- Offer gating: `src/crimson/gameplay.py`: perk generation rules.

## 40 — Ninja (`PerkId.NINJA`)

### Effects

- When taking damage, 1/3 chance to dodge completely (`rand % 3 == 0`).
- Takes precedence over Dodger.

### Original

- `player_take_damage` (0x00425e50): Ninja dodge check is evaluated before Dodger.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 41 — Highlander (`PerkId.HIGHLANDER`)

### Effects

- Incoming damage does not reduce health.
- Instead, each time a hit lands, there is a **10% chance** to die instantly (`rand % 10 == 0`).
- Normal “on-hit disruption” still applies unless Unstoppable is active.

### Original

- `player_take_damage` (0x00425e50): Highlander replacement behavior.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 42 — Jinxed (`PerkId.JINXED`)

### Effects

- Periodically:
  - has a 1/10 chance to deal **5 self-damage** (and emit two random decals),
  - and, if Freeze bonus is not active, may instantly kill a random creature and award its XP (no normal death handler).
- Uses a global timer that is randomized after each activation.

### Original

- `perks_update_effects` (0x00406b40): manages the timer and both the self-damage and random-creature-death branches.

### Rewrite

- `src/crimson/gameplay.py`: `perks_update_effects()` (Jinxed steps).

## 43 — Perk Master (`PerkId.PERK_MASTER`)

### Effects

- Perk selection offers **7 choices** instead of 5 (and instead of 6 with Perk Expert).

### Original

- Perk selection UI logic increases the choice count.

### Rewrite

- `src/crimson/gameplay.py`: `perk_choice_count()`.

## 44 — Reflex Boosted (`PerkId.REFLEX_BOOSTED`)

### Effects

- Global slow-motion effect: scales frame dt by **0.9** while active (i.e., the world runs ~10% slower).

### Original

- Main loop: when in gameplay state, `frame_dt *= 0.9` while active.

### Rewrite

- `src/crimson/sim/world_state.py`: `WorldState.step()`.

## 45 — Greater Regeneration (`PerkId.GREATER_REGENERATION`)

### Effects

- In this build, **no runtime effect** has been found (it appears to be a no-op perk).
- Death Clock clears its perk count on apply.

### Original

- No active tick/usage located in the authoritative decompile; only selection/apply bookkeeping references.

### Rewrite

- No runtime effect implemented (matches this build).
- Cleared by Death Clock apply: `src/crimson/gameplay.py`: Death Clock handler.

## 46 — Breathing Room (`PerkId.BREATHING_ROOM`)

### Effects

- Two-player-only perk.
- On pick:
  - reduces each alive player’s health to **1/3** (subtracts 2/3),
  - forces every active creature into the “death staging” path without awarding XP,
  - clears `bonus_spawn_guard`.

### Original

- `perk_apply` (0x004055e0): applies health reduction, forces creature hitbox ramp, clears guard.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Breathing Room handler).

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

### Original

- `perk_apply` (0x004055e0): clears regen perks and sets health to 100.
- `player_take_damage` (0x00425e50): early-return immunity.
- `perks_update_effects` (0x00406b40): per-frame drain logic.
- `bonus_pick_random_type` (0x00412470): medikit suppression while active.
- Perk offering: blocks multiple perks while active.

### Rewrite

- Apply and offer gating: `src/crimson/gameplay.py`: `perk_apply()`, perk generation, `bonus_pick_random_type()`.
- Damage immunity: `src/crimson/player_damage.py`: `player_take_damage()`.
- Drain tick: `src/crimson/gameplay.py`: `perks_update_effects()` (Death Clock step).

## 48 — My Favourite Weapon (`PerkId.MY_FAVOURITE_WEAPON`)

### Effects

- Increases clip size by **+2** (applied on pick and on weapon assignment).
- Weapon bonuses cannot spawn or be selected; picking up a weapon bonus is ignored.

### Original

- `perk_apply` (0x004055e0): immediate +2 clip size.
- `weapon_assign_player` (0x00452d40): applies +2 on assignment.
- Bonus selection/spawn logic removes weapon bonuses while active.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()`, `weapon_assign_player()`, `bonus_pick_random_type()`, `BonusPool.try_spawn_on_kill()`, `bonus_apply()`.

## 49 — Bandage (`PerkId.BANDAGE`)

### Effects

- Randomly multiplies current health by **1..50**, then clamps to **100**.
- Spawns an 8-particle burst effect.

### Original

- `perk_apply` (0x004055e0): random multiply + clamp + burst FX.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Bandage handler).

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

### Original

- `player_update` (0x004136b0): half-threshold detection and ring spawn.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()` reload perks section.

## 51 — Ion Gun Master (`PerkId.ION_GUN_MASTER`)

### Effects

- Ion blast damage multiplier: **×1.2**.
- Ion AoE radii are scaled by **×1.2** for ion weapons.
- The damage multiplier is global (not attacker-bound): any `damage_type == 7` damage is scaled while Ion Gun Master exists.

### Original

- `creature_apply_damage` (0x004207c0): ion damage scaling (damage type 7).
- `projectile_update` (0x00420b90): ion AoE scale.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- AoE radii: `src/crimson/projectiles.py`: ion behavior scaling.

## 52 — Stationary Reloader (`PerkId.STATIONARY_RELOADER`)

### Effects

- While stationary, reload speed is multiplied by **3.0**.

### Original

- `player_update` (0x004136b0): compares previous/current position to decide `reload_scale = 3.0`.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

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

### Original

- `player_update` (0x004136b0): timer accumulation/reset and ring spawn logic.

### Rewrite

- `src/crimson/gameplay.py`: `_perk_update_man_bomb()` and `player_update()`.

## 54 — Fire Caugh (`PerkId.FIRE_CAUGH`)

### Effects

- Periodically (interval randomized to 2–5 seconds):
  - plays two weapon-fire SFX,
  - spawns one Fire Bullets projectile from the muzzle:
    - muzzle is offset by a fixed `-0.150915` rad rotation (same muzzle convention as normal firing),
    - aim is jittered using the same distance-scaled spread model as normal firing (`dist * spread_heat`),
  - spawns a small grey sprite FX traveling forward from the muzzle.
- Projectile owner id depends on friendly-fire setting (`-100` when off, else `-1-player_index`).

### Original

- `player_update` (0x004136b0): timer and interval rerolling.
- Uses `projectile_spawn(..., PROJECTILE_TYPE_FIRE_BULLETS, owner_id)` plus `fx_spawn_sprite(...)`.

### Rewrite

- `src/crimson/gameplay.py`: `_perk_update_fire_cough()` and `player_update()` (sprite FX via `GameplayState.sprite_effects`).

## 55 — Living Fortress (`PerkId.LIVING_FORTRESS`)

### Effects

- While stationary, a timer ramps up to **30s**.
- Bullet damage scaling: for each alive player, bullet damage is multiplied by:
  `living_fortress_timer * 0.05 + 1.0`
  (with multiple alive players, the multiplier applies once per player).

### Original

- `player_update` (0x004136b0): timer accumulation/reset.
- `creature_apply_damage` (0x004207c0): bullet damage scaling.

### Rewrite

- Timer: `src/crimson/gameplay.py`: `player_update()`.
- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.

## 56 — Tough Reloader (`PerkId.TOUGH_RELOADER`)

### Effects

- While reloading (`reload_active != 0`), incoming damage is multiplied by **0.5**.

### Original

- `player_take_damage` (0x00425e50): checks `reload_active` and halves damage.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 57 — Lifeline 50-50 (`PerkId.LIFELINE_50_50`)

### Effects

- On pick, iterates the creature pool in slot order and removes roughly half of eligible creatures:
  - a toggle flips each slot; when “on”, and the creature is:
    - active,
    - `hp <= 500`,
    - `(flags & 4) == 0`,
    it is removed immediately (no normal death handling / no XP).
  - spawns a small burst FX per removed creature (4 particles).

### Original

- `perk_apply` (0x004055e0): direct deactivation in pool iteration order, plus burst FX.

### Rewrite

- `src/crimson/gameplay.py`: `perk_apply()` (Lifeline 50-50 handler).
