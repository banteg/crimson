---
tags:
  - reverse-engineering
  - static-analysis
  - perks
---

# Perk native call-site reference

This page maps perk behavior to the native functions that execute it in
Crimsonland v1.9.93. Resolve their current recovered bodies and binary views
through `just analysis-function <name-or-address>`.

Gameplay rules and exact effects live in [Perks](../../mechanics/perks.md).
Python execution phases are documented in [Perks architecture](../../rewrite/perks-architecture.md).
The implementation owners are:

| Responsibility | Python source |
| --- | --- |
| IDs, names, availability and choices | `src/crimson/perks/` |
| Immediate application and player/global ticks | `src/crimson/perks/runtime/`, `src/crimson/perks/impl/` |
| Player integration | `src/crimson/gameplay.py`, `src/crimson/player_damage.py` |
| Weapon assignment, reload and firing | `src/crimson/weapon_runtime/` |
| Creature damage and synchronous death | `src/crimson/creatures/damage.py`, `src/crimson/creatures/runtime.py` |
| Projectile hits and secondary behavior | `src/crimson/projectiles/runtime/` |
| Bonus selection and pickup | `src/crimson/bonuses/` |
| Perk menu and overlays | `src/crimson/ui/perk_menu.py`, `src/crimson/render/world/` |

Counts live on `PlayerState.perk_counts`; shared perk acquisition mirrors them
from the owner to the other local players. Do not infer execution order from ID
order: a perk can act in several native paths.

## 0. AntiPerk (`PerkId.ANTIPERK`)

### Original

- `perk_can_offer` (0x0042fb10): explicitly rejects `perk_id_antiperk`.


## 1. Bloody Mess / Quick Learner (`PerkId.BLOODY_MESS_QUICK_LEARNER`)

### Original

- Kill XP: creature death handling (via `creature_update_all` → `creature_handle_death` path).
- Hit FX: projectile hit handling queues extra decals / blood splatter when the perk is active and blood is enabled.


## 2. Sharpshooter (`PerkId.SHARPSHOOTER`)

### Original

- `player_update` (0x004136b0): forces `spread_heat = 0.02` while active.
- `player_fire_weapon` (0x00444980): applies `shot_cooldown *= 1.05` and avoids the normal post-shot spread heat increase.
- Rendering: draws the laser overlay in the player render path.


## 3. Fastloader (`PerkId.FASTLOADER`)

### Original

- `player_start_reload` (0x00413430): applies the multiplier when starting a reload.


## 4. Lean Mean Exp. Machine (`PerkId.LEAN_MEAN_EXP_MACHINE`)

### Original

- `perks_update_effects` (0x00406b40): timer-based periodic XP grant.


## 5. Long Distance Runner (`PerkId.LONG_DISTANCE_RUNNER`)

### Original

- `player_update` (0x004136b0): move-speed ramp/decay logic with perk-enabled extension to 2.8.


## 6. Pyrokinetic (`PerkId.PYROKINETIC`)

### Original

- `perks_update_effects` (0x00406b40): selects an aim target via `creature_find_in_radius(..., 12.0, 0)` and runs the timer/FX emission.
- The flare itself only spawns FX, but the five `fx_spawn_particle` flames (intensities 0.8/0.6/0.4/0.3/0.2) deal damage downstream: the particle loop in `projectile_update` (0x00420b90) calls `creature_apply_damage(idx, intensity * 10.0, 4, ...)` on contact and darkens the creature tint, so Pyrokinetic damages creatures.


## 7. Instant Winner (`PerkId.INSTANT_WINNER`)

### Original

- `perk_apply` (0x004055e0): adds 2500 XP.


## 8. Grim Deal (`PerkId.GRIM_DEAL`)

### Original

- `perk_apply` (0x004055e0): `experience += int(experience * 0.18)` then `health = -1.0`.


## 9. Alternate Weapon (`PerkId.ALTERNATE_WEAPON`)

### Original

- `player_apply_move_with_spawn_avoidance` (0x0041e290): movement scaling.
- `player_update` (0x004136b0): reload-triggered swap behavior + shot cooldown bump.
- `perk_can_offer` (0x0042fb10): mode-flag gating (`flags & 0x2`) prevents offers in two-player.


## 10. Plaguebearer (`PerkId.PLAGUEBEARER`)

### Original

- `perk_apply` (0x004055e0): sets `player_plaguebearer_active` (global-ish field on player0).
- `creature_update_all` (0x00426220): infection flagging, ticking, spread (`plaguebearer_spread_infection`), and infection kill bookkeeping.
- `perk_can_offer` (0x0042fb10): hardcore quest 2-10 special-case blocks Plaguebearer.


## 11. Evil Eyes (`PerkId.EVIL_EYES`)

### Original

- `perks_update_effects` (0x00406b40): updates `evil_eyes_target_creature` via `creature_find_in_radius`.
- `creature_update_all` (0x00426220): skips AI update for the targeted creature.


## 12. Ammo Maniac (`PerkId.AMMO_MANIAC`)

### Original

- `perk_apply` (0x004055e0): reassigns each player's current weapon to force clip recalculation.
- `weapon_assign_player` (0x00452d40): applies the clip-size modifier.


## 13. Radioactive (`PerkId.RADIOACTIVE`)

### Original

- `creature_update_all` (0x00426220): proximity check, timer wrap, falloff damage; special-case kill/XP handling.
- Rendering: draws the player aura (effect atlas id `0x10`).


## 14. Fastshot (`PerkId.FASTSHOT`)

### Original

- `player_fire_weapon` (0x00444980): applies the cooldown multiplier.


## 15. Fatal Lottery (`PerkId.FATAL_LOTTERY`)

### Original

- `perk_apply` (0x004055e0): `(crt_rand() & 1)` decides XP vs death.
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects the perk in quest mode and two-player.


## 16. Random Weapon (`PerkId.RANDOM_WEAPON`)

### Original

- `perk_apply` (0x004055e0): random selection (`weapon_pick_random_available`) with up to 100 retries to avoid pistol/current, then `weapon_assign_player` with the last roll.


## 17. Mr. Melee (`PerkId.MR_MELEE`)

### Original

- `creature_update_all` (0x00426220): on contact-damage tick, calls `creature_apply_damage(attacker, 25, damage_type=2, impulse=(0,0))` when Mr. Melee is active, without suppressing the player damage path.


## 18. Anxious Loader (`PerkId.ANXIOUS_LOADER`)

### Original

- `player_update` (0x004136b0): checks `input_primary_just_pressed()` and applies the timer reduction.


## 19. Final Revenge (`PerkId.FINAL_REVENGE`)

### Original

- `player_take_damage` (0x00425e50): death check triggers the revenge burst and radial damage via `creature_apply_damage` (damage type 3).
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects the perk in quest mode and two-player.


## 20. Telekinetic (`PerkId.TELEKINETIC`)

### Original

- Bonus update logic uses a per-player aim-hover timer and a fixed delay threshold.


## 21. Perk Expert (`PerkId.PERK_EXPERT`)

### Original

- Perk selection UI logic adjusts choice count and layout while the perk is active.


## 22. Unstoppable (`PerkId.UNSTOPPABLE`)

### Original

- `player_take_damage` (0x00425e50): gates the disruption logic on perk presence.


## 23. Regression Bullets (`PerkId.REGRESSION_BULLETS`)

### Original

- `player_fire_weapon` (0x00444980): implements the "fire during reload by paying XP" path; this branch is gated by `experience > 0`.
- `player_start_reload` (0x00413430): reload restart guard when Regression Bullets or Ammunition Within is active.


## 24. Infernal Contract (`PerkId.INFERNAL_CONTRACT`)

### Original

- `perk_apply` (0x004055e0): applies the health reduction and perk/level grants.
- Perk offering logic blocks the perk under Death Clock.


## 25. Poison Bullets (`PerkId.POISON_BULLETS`)

### Original

- `projectile_update` (0x00420b90): sets weak poison on hit (`flags |= 0x01`) when `(crt_rand() & 7) == 1`.
- `creature_update_all` (0x00426220): applies self-damage using `creature_apply_damage(..., damage_type=0, impulse=(0,0))`.
- Toxic Avenger does not modify this projectile-hit poison branch; strong poison (`flags |= 0x02`) comes from Toxic Avenger melee retaliation in `creature_update_all`.
- Rendering: creature overlay draws aura `0x10` when poison flag is set.
- `perk_can_offer` (0x0042fb10): hardcore quest 2-10 special-case blocks Poison Bullets.


## 26. Dodger (`PerkId.DODGER`)

### Original

- `player_take_damage` (0x00425e50): Dodger is `crt_rand() % 5 == 0` if Ninja is not active.


## 27. Bonus Magnet (`PerkId.BONUS_MAGNET`)

### Original

- Bonus spawn-on-kill logic (`bonus_try_spawn_on_kill`): additional roll gates on perk.


## 28. Uranium Filled Bullets (`PerkId.URANIUM_FILLED_BULLETS`)

### Original

- `creature_apply_damage` (0x004207c0): when `damage_type == 1`, doubles damage.


## 29. Doctor (`PerkId.DOCTOR`)

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- Target selection: uses `creature_find_in_radius(aim, 12.0, 0)`.
- HUD draw: draws a 64px bar with the clamped `health/max_health` ratio.


## 30. Monster Vision (`PerkId.MONSTER_VISION`)

### Original

- Selection: no FX-detail offer gate in `perks_generate_choices`; Monster Vision is part of the 25% rarity reject group.
- Rendering: creature render pass draws `0x10` behind creatures; shadow pass is disabled while active.


## 31. Hot Tempered (`PerkId.HOT_TEMPERED`)

### Original

- `player_update` (0x004136b0): timer logic + randomized interval + ring spawn.


## 32. Bonus Economist (`PerkId.BONUS_ECONOMIST`)

### Original

- Bonus application scales duration increments while the perk is active.


## 33. Thick Skinned (`PerkId.THICK_SKINNED`)

### Original

- `perk_apply` (0x004055e0): health scaling on pick.
- `player_take_damage` (0x00425e50): damage scaling.
- Perk offering blocks it under Death Clock.


## 34. Barrel Greaser (`PerkId.BARREL_GREASER`)

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- `projectile_update` (0x00420b90): doubles the movement step count when the perk is active and the projectile is player-owned.


## 35. Ammunition Within (`PerkId.AMMUNITION_WITHIN`)

### Original

- `player_fire_weapon` (0x00444980): implements the "fire during reload by paying health" path; this branch is also gated by `experience > 0`.
- `player_start_reload` (0x00413430): restart guard.


## 36. Veins of Poison (`PerkId.VEINS_OF_POISON`)

### Original

- `creature_update_all` (0x00426220): on contact-damage, checks `shield_timer` and sets poison flags.
- Perk offering: hardcore quest gating.


## 37. Toxic Avenger (`PerkId.TOXIC_AVENGER`)

### Original

- `creature_update_all` (0x00426220): sets both weak+strong poison flags.


## 38. Regeneration (`PerkId.REGENERATION`)

### Original

- `perks_update_effects` (0x00406b40): heal loop.


## 39. Pyromaniac (`PerkId.PYROMANIAC`)

### Original

- `creature_apply_damage` (0x004207c0): fire damage scaling and a `crt_rand()` side-effect.
- Perk offering logic gates by current weapon.


## 40. Ninja (`PerkId.NINJA`)

### Original

- `player_take_damage` (0x00425e50): Ninja dodge check is evaluated before Dodger.


## 41. Highlander (`PerkId.HIGHLANDER`)

### Original

- `player_take_damage` (0x00425e50): Highlander replacement behavior.
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects Highlander in quest mode and two-player.
- `perks_generate_choices` (0x00430160): Death Clock active path rejects Highlander from offers.


## 42. Jinxed (`PerkId.JINXED`)

### Original

- `perks_update_effects` (0x00406b40): manages the timer and both the self-damage and random-creature-death branches.


## 43. Perk Master (`PerkId.PERK_MASTER`)

### Original

- Perk selection UI logic increases the choice count.


## 44. Reflex Boosted (`PerkId.REFLEX_BOOSTED`)

### Original

- Main loop: when in gameplay state, `frame_dt *= 0.9` while active.


## 45. Greater Regeneration (`PerkId.GREATER_REGENERATION`)

### Original

- No active tick/usage located in the authoritative decompile; only selection/apply bookkeeping references.


## 46. Breathing Room (`PerkId.BREATHING_ROOM`)

### Original

- `perk_apply` (0x004055e0): applies health reduction, advances the creature lifecycle stage, clears guard.


## 47. Death Clock (`PerkId.DEATH_CLOCK`)

### Original

- `perk_apply` (0x004055e0): clears regen perks and sets health to 100.
- `player_take_damage` (0x00425e50): early-return immunity.
- `projectile_update` (0x00420b90): player-hit path directly subtracts fixed projectile damage (bypasses `player_take_damage`).
- `perks_update_effects` (0x00406b40): per-frame drain logic.
- `bonus_pick_random_type` (0x00412470): medikit suppression while active.
- Perk offering: blocks multiple perks while active.


## 48. My Favourite Weapon (`PerkId.MY_FAVOURITE_WEAPON`)

### Original

- `perk_apply` (0x004055e0): immediate +2 clip size.
- `weapon_assign_player` (0x00452d40): applies +2 on assignment.
- Bonus selection/spawn logic removes weapon bonuses while active.


## 49. Bandage (`PerkId.BANDAGE`)

### Original

- `perk_apply` (0x004055e0): random multiply + clamp + burst FX.


## 50. Angry Reloader (`PerkId.ANGRY_RELOADER`)

### Original

- `player_update` (0x004136b0): half-threshold detection and ring spawn.


## 51. Ion Gun Master (`PerkId.ION_GUN_MASTER`)

### Original

- `creature_apply_damage` (0x004207c0): ion damage scaling (damage type 7).
- `projectile_update` (0x00420b90): ion AoE scale.


## 52. Stationary Reloader (`PerkId.STATIONARY_RELOADER`)

### Original

- `player_update` (0x004136b0): compares previous/current position to decide `reload_scale = 3.0`.


## 53. Man Bomb (`PerkId.MAN_BOMB`)

### Original

- `player_update` (0x004136b0): timer accumulation/reset and ring spawn logic.
- Ordering detail: `player_man_bomb_timer` is incremented/checked before the
  later movement gate clears it (`player_state + 0x7c = 0`) when position changed.


## 54. Fire Cough (`PerkId.FIRE_CAUGH`)

### Original

- `player_update` (0x004136b0): timer and interval rerolling.
- Uses `projectile_spawn(..., PROJECTILE_TYPE_FIRE_BULLETS, owner_id)` plus `fx_spawn_sprite(...)`.


## 55. Living Fortress (`PerkId.LIVING_FORTRESS`)

### Original

- `player_update` (0x004136b0): timer accumulation/reset.
- `creature_apply_damage` (0x004207c0): bullet damage scaling.


## 56. Tough Reloader (`PerkId.TOUGH_RELOADER`)

### Original

- `player_take_damage` (0x00425e50): checks `reload_active` and halves damage.


## 57. Lifeline 50-50 (`PerkId.LIFELINE_50_50`)

### Original

- `perk_apply` (0x004055e0): direct deactivation in pool iteration order, plus burst FX.
