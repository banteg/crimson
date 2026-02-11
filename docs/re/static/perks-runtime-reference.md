---
tags:
  - reverse-engineering
  - static-analysis
  - perks
---

# Perk Runtime Reference

This page documents runtime location evidence for each perk in:

- **Original**: Crimsonland v1.9.93 (`analysis/ghidra/raw/crimsonland.exe_decompiled.c`)
- **Rewrite parity implementation**: Python port (`src/`)

For gameplay effects and mechanics, see [Perks](../../mechanics/perks.md).
For ID/name mapping and init metadata, see [Perk ID map](../../perk-id-map.md).

Notes:

- Many perk effects are implemented by a small set of hot paths in the original:
  `perk_apply` (0x004055e0), `perks_update_effects` (0x00406b40), `player_update` (0x004136b0),
  `player_fire_weapon` (0x00444980), `player_take_damage` (0x00425e50),
  `creature_update_all` (0x00426220), `creature_apply_damage` (0x004207c0),
  `projectile_update` (0x00420b90), and rendering passes.
- In the rewrite, perk counts live on `PlayerState.perk_counts` and are typically treated as shared state across players (synced from player 0).

## 0. AntiPerk (`PerkId.ANTIPERK`)

### Original

- `perk_can_offer` (0x0042fb10): explicitly rejects `perk_id_antiperk`.

### Rewrite

- `src/crimson/perks/availability.py`: `perk_can_offer()` rejects `PerkId.ANTIPERK`.

## 1. Bloody Mess / Quick Learner (`PerkId.BLOODY_MESS_QUICK_LEARNER`)

### Original

- Kill XP: creature death handling (via `creature_update_all` → `creature_handle_death` path).
- Hit FX: projectile hit handling queues extra decals / blood splatter when the perk is active and blood is enabled.

### Rewrite

- XP multiplier on kill: `src/crimson/creatures/runtime.py`: `CreaturePool._start_death()`.
- Extra hit decals/blood: `src/crimson/game_world.py`: `GameWorld._queue_projectile_decals()`.
- Name/description toggle: `src/crimson/perks/ids.py`: `perk_display_name()` / `perk_display_description()`.

## 2. Sharpshooter (`PerkId.SHARPSHOOTER`)

### Original

- `player_update` (0x004136b0): forces `spread_heat = 0.02` while active.
- `player_fire_weapon` (0x00444980): applies `shot_cooldown *= 1.05` and avoids the normal post-shot spread heat increase.
- Rendering: draws the laser overlay in the player render path.

### Rewrite

- Shot cooldown and spread behavior: `src/crimson/gameplay.py`: `player_fire_weapon()`, `player_update()`.
- Laser rendering: `src/crimson/render/world_renderer.py`: `_draw_sharpshooter_laser_sight()`.

## 3. Fastloader (`PerkId.FASTLOADER`)

### Original

- `player_start_reload` (0x00413430): applies the multiplier when starting a reload.

### Rewrite

- `src/crimson/gameplay.py`: `player_start_reload()`.

## 4. Lean Mean Exp. Machine (`PerkId.LEAN_MEAN_EXP_MACHINE`)

### Original

- `perks_update_effects` (0x00406b40): timer-based periodic XP grant.

### Rewrite

- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Lean Mean step: `src/crimson/perks/impl/lean_mean_exp_machine_effect.py`: `update_lean_mean_exp_machine()`.

## 5. Long Distance Runner (`PerkId.LONG_DISTANCE_RUNNER`)

### Original

- `player_update` (0x004136b0): move-speed ramp/decay logic with perk-enabled extension to 2.8.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

## 6. Pyrokinetic (`PerkId.PYROKINETIC`)

### Original

- `perks_update_effects` (0x00406b40): selects an aim target via `creature_find_in_radius(..., 12.0, 0)` and runs the timer/FX emission.

### Rewrite

- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Pyrokinetic step: `src/crimson/perks/impl/pyrokinetic_effect.py`: `update_pyrokinetic()`.

## 7. Instant Winner (`PerkId.INSTANT_WINNER`)

### Original

- `perk_apply` (0x004055e0): adds 2500 XP.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/instant_winner.py`: `apply_instant_winner()`.

## 8. Grim Deal (`PerkId.GRIM_DEAL`)

### Original

- `perk_apply` (0x004055e0): `experience += int(experience * 0.18)` then `health = -1.0`.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/grim_deal.py`: `apply_grim_deal()`.

## 9. Alternate Weapon (`PerkId.ALTERNATE_WEAPON`)

### Original

- `player_apply_move_with_spawn_avoidance` (0x0041e290): movement scaling.
- `player_update` (0x004136b0): reload-triggered swap behavior + shot cooldown bump.
- `perk_can_offer` (0x0042fb10): mode-flag gating (`flags & 0x2`) prevents offers in two-player.

### Rewrite

- Swap and carry behavior: `src/crimson/gameplay.py`: `player_swap_alt_weapon()`, `player_update()`.
- Bonus application during swap path: `src/crimson/bonuses/apply.py`: `bonus_apply()`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`.

## 10. Plaguebearer (`PerkId.PLAGUEBEARER`)

### Original

- `perk_apply` (0x004055e0): sets `player_plaguebearer_active` (global-ish field on player0).
- `creature_update_all` (0x00426220): infection flagging, ticking, spread (`plaguebearer_spread_infection`), and infection kill bookkeeping.
- `perk_can_offer` (0x0042fb10): hardcore quest 2-10 special-case blocks Plaguebearer.

### Rewrite

- Flag application: `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/plaguebearer.py`: `apply_plaguebearer()` (sets `plaguebearer_active` for all players).
- Creature-side behavior: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (contact infection, tick damage, spread).
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()` hardcore quest gate.

## 11. Evil Eyes (`PerkId.EVIL_EYES`)

### Original

- `perks_update_effects` (0x00406b40): updates `evil_eyes_target_creature` via `creature_find_in_radius`.
- `creature_update_all` (0x00426220): skips AI update for the targeted creature.

### Rewrite

- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Evil Eyes step: `src/crimson/perks/impl/evil_eyes_effect.py`: `update_evil_eyes_target()`.
- Freeze behavior: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (evil-eyes target handling).

## 12. Ammo Maniac (`PerkId.AMMO_MANIAC`)

### Original

- `perk_apply` (0x004055e0): reassigns each player's current weapon to force clip recalculation.
- `weapon_assign_player` (0x00452d40): applies the clip-size modifier.

### Rewrite

- Clip sizing: `src/crimson/gameplay.py`: `weapon_assign_player()` (Ammo Maniac modifier).
- Apply-time reassignment: `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/ammo_maniac.py`: `apply_ammo_maniac()`.

## 13. Radioactive (`PerkId.RADIOACTIVE`)

### Original

- `creature_update_all` (0x00426220): proximity check, timer wrap, falloff damage; special-case kill/XP handling.
- Rendering: draws the player aura (effect atlas id `0x10`).

### Rewrite

- Gameplay: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` (Radioactive tick and kill handling).
- Rendering: `src/crimson/render/world_renderer.py`: player aura in `_draw_player_trooper_sprite()`.

## 14. Fastshot (`PerkId.FASTSHOT`)

### Original

- `player_fire_weapon` (0x00444980): applies the cooldown multiplier.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()`.

## 15. Fatal Lottery (`PerkId.FATAL_LOTTERY`)

### Original

- `perk_apply` (0x004055e0): `(crt_rand() & 1)` decides XP vs death.
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects the perk in quest mode and two-player.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/fatal_lottery.py`: `apply_fatal_lottery()`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`.

## 16. Random Weapon (`PerkId.RANDOM_WEAPON`)

### Original

- `perk_apply` (0x004055e0): random selection (`weapon_pick_random_available`) with up to 100 retries to avoid pistol/current, then `weapon_assign_player` with the last roll.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/random_weapon.py`: `apply_random_weapon()`.

## 17. Mr. Melee (`PerkId.MR_MELEE`)

### Original

- `creature_update_all` (0x00426220): on contact-damage tick, calls `creature_apply_damage(attacker, 25, damage_type=2, impulse=(0,0))` when Mr. Melee is active, without suppressing the player damage path.

### Rewrite

- `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()` (Mr. Melee branch + deferred death handling).

## 18. Anxious Loader (`PerkId.ANXIOUS_LOADER`)

### Original

- `player_update` (0x004136b0): checks `input_primary_just_pressed()` and applies the timer reduction.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

## 19. Final Revenge (`PerkId.FINAL_REVENGE`)

### Original

- `player_take_damage` (0x00425e50): death check triggers the revenge burst and radial damage via `creature_apply_damage` (damage type 3).
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects the perk in quest mode and two-player.

### Rewrite

- Death hook implementation: `src/crimson/perks/impl/final_revenge.py`: `apply_final_revenge_on_player_death()`.
- Hook wiring and death pipeline call-site: `src/crimson/sim/world_state.py`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`.

## 20. Telekinetic (`PerkId.TELEKINETIC`)

### Original

- Bonus update logic uses a per-player aim-hover timer and a fixed delay threshold.

### Rewrite

- `src/crimson/bonuses/update.py`: `bonus_telekinetic_update()`.
- `src/crimson/bonuses/pool.py`: `bonus_find_aim_hover_entry()`.

## 21. Perk Expert (`PerkId.PERK_EXPERT`)

### Original

- Perk selection UI logic adjusts choice count and layout while the perk is active.

### Rewrite

- Choice count: `src/crimson/perks/selection.py`: `perk_choice_count()`.
- UI layout + sponsor text: `src/crimson/ui/perk_menu.py`, `src/crimson/views/perks.py`.

## 22. Unstoppable (`PerkId.UNSTOPPABLE`)

### Original

- `player_take_damage` (0x00425e50): gates the disruption logic on perk presence.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 23. Regression Bullets (`PerkId.REGRESSION_BULLETS`)

### Original

- `player_fire_weapon` (0x00444980): implements the "fire during reload by paying XP" path; this branch is gated by `experience > 0`.
- `player_start_reload` (0x00413430): reload restart guard when Regression Bullets or Ammunition Within is active.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()` (reload firing + XP drain), `player_start_reload()` (restart guard).

## 24. Infernal Contract (`PerkId.INFERNAL_CONTRACT`)

### Original

- `perk_apply` (0x004055e0): applies the health reduction and perk/level grants.
- Perk offering logic blocks the perk under Death Clock.

### Rewrite

- Apply: `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/infernal_contract.py`: `apply_infernal_contract()`.
- Selection/gating: `src/crimson/perks/selection.py`: `perk_generate_choices()`.

## 25. Poison Bullets (`PerkId.POISON_BULLETS`)

### Original

- `projectile_update` (0x00420b90): sets weak poison on hit (`flags |= 0x01`) when `(crt_rand() & 7) == 1`.
- `creature_update_all` (0x00426220): applies self-damage using `creature_apply_damage(..., damage_type=0, impulse=(0,0))`.
- Toxic Avenger does not modify this projectile-hit poison branch; strong poison (`flags |= 0x02`) comes from Toxic Avenger melee retaliation in `creature_update_all`.
- Rendering: creature overlay draws aura `0x10` when poison flag is set.
- `perk_can_offer` (0x0042fb10): hardcore quest 2-10 special-case blocks Poison Bullets.

### Rewrite

- Poison flagging: `src/crimson/projectiles.py`: `ProjectilePool.update()` hit logic.
- Poison tick: `src/crimson/creatures/runtime.py`: `CreaturePool.update()` routes self-damage through `creature_apply_damage()`.
- Aura render: `src/crimson/render/world_renderer.py`: creature overlay in `WorldRenderer.draw()`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()` hardcore quest gate.

## 26. Dodger (`PerkId.DODGER`)

### Original

- `player_take_damage` (0x00425e50): Dodger is `crt_rand() % 5 == 0` if Ninja is not active.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 27. Bonus Magnet (`PerkId.BONUS_MAGNET`)

### Original

- Bonus spawn-on-kill logic (`bonus_try_spawn_on_kill`): additional roll gates on perk.

### Rewrite

- `src/crimson/bonuses/pool.py`: `BonusPool.try_spawn_on_kill()`.

## 28. Uranium Filled Bullets (`PerkId.URANIUM_FILLED_BULLETS`)

### Original

- `creature_apply_damage` (0x004207c0): when `damage_type == 1`, doubles damage.

### Rewrite

- `src/crimson/creatures/damage.py`: `creature_apply_damage()`.

## 29. Doctor (`PerkId.DOCTOR`)

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- Target selection: uses `creature_find_in_radius(aim, 12.0, 0)`.
- HUD draw: draws a 64px bar with the clamped `health/max_health` ratio.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- UI: `src/crimson/modes/base_gameplay_mode.py`: `_draw_target_health_bar()`, and `src/crimson/ui/hud.py`: `draw_target_health_bar()`.

## 30. Monster Vision (`PerkId.MONSTER_VISION`)

### Original

- Selection: no FX-detail offer gate in `perks_generate_choices`; Monster Vision is part of the 25% rarity reject group.
- Rendering: creature render pass draws `0x10` behind creatures; shadow pass is disabled while active.

### Rewrite

- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`.
- Perk selection: `src/crimson/perks/selection.py`: `perk_generate_choices()`.
- Rendering: `src/crimson/render/world_renderer.py`: `WorldRenderer.draw()` (Monster Vision overlay and shadow gating).

## 31. Hot Tempered (`PerkId.HOT_TEMPERED`)

### Original

- `player_update` (0x004136b0): timer logic + randomized interval + ring spawn.

### Rewrite

- `src/crimson/perks/impl/hot_tempered.py`: `tick_hot_tempered()`.

## 32. Bonus Economist (`PerkId.BONUS_ECONOMIST`)

### Original

- Bonus application scales duration increments while the perk is active.

### Rewrite

- `src/crimson/bonuses/apply.py`: `bonus_apply()` (economist multiplier).

## 33. Thick Skinned (`PerkId.THICK_SKINNED`)

### Original

- `perk_apply` (0x004055e0): health scaling on pick.
- `player_take_damage` (0x00425e50): damage scaling.
- Perk offering blocks it under Death Clock.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/thick_skinned.py`: `apply_thick_skinned()`.
- `src/crimson/player_damage.py`: `player_take_damage()`.
- Offer gating: `src/crimson/perks/selection.py`: `perk_generate_choices()`.

## 34. Barrel Greaser (`PerkId.BARREL_GREASER`)

### Original

- `creature_apply_damage` (0x004207c0): bullet damage scaling.
- `projectile_update` (0x00420b90): doubles the movement step count when the perk is active and the projectile is player-owned.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- Projectile stepping: `src/crimson/projectiles.py`: `ProjectilePool.update()`.

## 35. Ammunition Within (`PerkId.AMMUNITION_WITHIN`)

### Original

- `player_fire_weapon` (0x00444980): implements the "fire during reload by paying health" path; this branch is also gated by `experience > 0`.
- `player_start_reload` (0x00413430): restart guard.

### Rewrite

- `src/crimson/gameplay.py`: `player_fire_weapon()` and `player_start_reload()`.

## 36. Veins of Poison (`PerkId.VEINS_OF_POISON`)

### Original

- `creature_update_all` (0x00426220): on contact-damage, checks `shield_timer` and sets poison flags.
- Perk offering: hardcore quest gating.

### Rewrite

- Contact poison flagging: `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`.

## 37. Toxic Avenger (`PerkId.TOXIC_AVENGER`)

### Original

- `creature_update_all` (0x00426220): sets both weak+strong poison flags.

### Rewrite

- `src/crimson/creatures/runtime.py`: `_creature_interaction_contact_damage()`.

## 38. Regeneration (`PerkId.REGENERATION`)

### Original

- `perks_update_effects` (0x00406b40): heal loop.

### Rewrite

- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Regeneration step: `src/crimson/perks/impl/regeneration_effect.py`: `update_regeneration()`.

## 39. Pyromaniac (`PerkId.PYROMANIAC`)

### Original

- `creature_apply_damage` (0x004207c0): fire damage scaling and a `crt_rand()` side-effect.
- Perk offering logic gates by current weapon.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- Offer gating: `src/crimson/perks/selection.py`: perk generation rules (`perk_generate_choices()` weapon gate).

## 40. Ninja (`PerkId.NINJA`)

### Original

- `player_take_damage` (0x00425e50): Ninja dodge check is evaluated before Dodger.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 41. Highlander (`PerkId.HIGHLANDER`)

### Original

- `player_take_damage` (0x00425e50): Highlander replacement behavior.
- `perk_can_offer` (0x0042fb10): mode-flag gating rejects Highlander in quest mode and two-player.
- `perks_generate_choices` (0x00430160): Death Clock active path rejects Highlander from offers.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.
- Offer gating: `src/crimson/perks/availability.py`: `perk_can_offer()`, plus Death Clock block in `src/crimson/perks/selection.py`: `perk_generate_choices()`.

## 42. Jinxed (`PerkId.JINXED`)

### Original

- `perks_update_effects` (0x00406b40): manages the timer and both the self-damage and random-creature-death branches.

### Rewrite

- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Jinxed steps: `src/crimson/perks/impl/jinxed_effect.py`: `update_jinxed_timer()`, `update_jinxed()`.

## 43. Perk Master (`PerkId.PERK_MASTER`)

### Original

- Perk selection UI logic increases the choice count.

### Rewrite

- `src/crimson/perks/selection.py`: `perk_choice_count()`.

## 44. Reflex Boosted (`PerkId.REFLEX_BOOSTED`)

### Original

- Main loop: when in gameplay state, `frame_dt *= 0.9` while active.

### Rewrite

- `src/crimson/sim/world_state.py`: `WorldState.step()`.

## 45. Greater Regeneration (`PerkId.GREATER_REGENERATION`)

### Original

- No active tick/usage located in the authoritative decompile; only selection/apply bookkeeping references.

### Rewrite

- Default rewrite mode: Greater Regeneration upgrades Regeneration heal ticks
  from `+dt` to `+2*dt` (same RNG gate in `perks_update_effects`).
- With `--preserve-bugs`: no runtime effect (matches original).
- Implementation: `src/crimson/perks/impl/regeneration_effect.py`: `update_regeneration()`.
- Cleared by Death Clock apply: `src/crimson/perks/impl/death_clock.py`: `apply_death_clock()`.

## 46. Breathing Room (`PerkId.BREATHING_ROOM`)

### Original

- `perk_apply` (0x004055e0): applies health reduction, forces creature hitbox ramp, clears guard.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/breathing_room.py`: `apply_breathing_room()`.

## 47. Death Clock (`PerkId.DEATH_CLOCK`)

### Original

- `perk_apply` (0x004055e0): clears regen perks and sets health to 100.
- `player_take_damage` (0x00425e50): early-return immunity.
- `projectile_update` (0x00420b90): player-hit path directly subtracts fixed projectile damage (bypasses `player_take_damage`).
- `perks_update_effects` (0x00406b40): per-frame drain logic.
- `bonus_pick_random_type` (0x00412470): medikit suppression while active.
- Perk offering: blocks multiple perks while active.

### Rewrite

- Apply: `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/death_clock.py`: `apply_death_clock()`.
- Offer gating: `src/crimson/perks/selection.py`: `perk_generate_choices()`.
- Medikit suppression: `src/crimson/gameplay.py`: `bonus_pick_random_type()`.
- Damage immunity: `src/crimson/player_damage.py`: `player_take_damage()`.
- Projectile player-hit damage path: `src/crimson/player_damage.py`: `player_take_projectile_damage()`, called from `src/crimson/projectiles.py`: `ProjectilePool.update()`.
- `src/crimson/perks/runtime/effects.py`: `perks_update_effects()`.
- Death Clock step: `src/crimson/perks/impl/death_clock.py`: `update_death_clock()`.

## 48. My Favourite Weapon (`PerkId.MY_FAVOURITE_WEAPON`)

### Original

- `perk_apply` (0x004055e0): immediate +2 clip size.
- `weapon_assign_player` (0x00452d40): applies +2 on assignment.
- Bonus selection/spawn logic removes weapon bonuses while active.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/my_favourite_weapon.py`: `apply_my_favourite_weapon()`.
- `src/crimson/gameplay.py`: `weapon_assign_player()`, `bonus_pick_random_type()`.
- `src/crimson/bonuses/pool.py`: `BonusPool.try_spawn_on_kill()`.
- `src/crimson/bonuses/apply.py`: `bonus_apply()`.

## 49. Bandage (`PerkId.BANDAGE`)

### Original

- `perk_apply` (0x004055e0): random multiply + clamp + burst FX.

### Rewrite

- Default rewrite mode: heals `+1..+50` HP (clamped to 100), matching the
  in-game perk description text.
- With `--preserve-bugs`: keeps the native multiplier behavior (`health *= 1..50`).
- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/bandage.py`: `apply_bandage()`.

## 50. Angry Reloader (`PerkId.ANGRY_RELOADER`)

### Original

- `player_update` (0x004136b0): half-threshold detection and ring spawn.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()` reload perks section.

## 51. Ion Gun Master (`PerkId.ION_GUN_MASTER`)

### Original

- `creature_apply_damage` (0x004207c0): ion damage scaling (damage type 7).
- `projectile_update` (0x00420b90): ion AoE scale.

### Rewrite

- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.
- AoE radii: `src/crimson/projectiles.py`: ion behavior scaling.

## 52. Stationary Reloader (`PerkId.STATIONARY_RELOADER`)

### Original

- `player_update` (0x004136b0): compares previous/current position to decide `reload_scale = 3.0`.

### Rewrite

- `src/crimson/gameplay.py`: `player_update()`.

## 53. Man Bomb (`PerkId.MAN_BOMB`)

### Original

- `player_update` (0x004136b0): timer accumulation/reset and ring spawn logic.
- Ordering detail: `player_man_bomb_timer` is incremented/checked before the
  later movement gate clears it (`player_state + 0x7c = 0`) when position changed.

### Rewrite

- `src/crimson/perks/impl/man_bomb.py`: `tick_man_bomb()` mirrors native ordering
  (burst check first, movement reset after).
- Movement/stationary state feed: `src/crimson/gameplay.py`: `player_update()`.

## 54. Fire Cough (`PerkId.FIRE_CAUGH`)

### Original

- `player_update` (0x004136b0): timer and interval rerolling.
- Uses `projectile_spawn(..., PROJECTILE_TYPE_FIRE_BULLETS, owner_id)` plus `fx_spawn_sprite(...)`.

### Rewrite

- `src/crimson/perks/impl/fire_cough.py`: `tick_fire_cough()`.
- Player aim/input feed: `src/crimson/gameplay.py`: `player_update()` (sprite FX via `GameplayState.sprite_effects`).

## 55. Living Fortress (`PerkId.LIVING_FORTRESS`)

### Original

- `player_update` (0x004136b0): timer accumulation/reset.
- `creature_apply_damage` (0x004207c0): bullet damage scaling.

### Rewrite

- Timer: `src/crimson/gameplay.py`: `player_update()`.
- Damage: `src/crimson/creatures/damage.py`: `creature_apply_damage()`.

## 56. Tough Reloader (`PerkId.TOUGH_RELOADER`)

### Original

- `player_take_damage` (0x00425e50): checks `reload_active` and halves damage.

### Rewrite

- `src/crimson/player_damage.py`: `player_take_damage()`.

## 57. Lifeline 50-50 (`PerkId.LIFELINE_50_50`)

### Original

- `perk_apply` (0x004055e0): direct deactivation in pool iteration order, plus burst FX.

### Rewrite

- `src/crimson/perks/runtime/apply.py`: `perk_apply()` dispatches to:
- `src/crimson/perks/impl/lifeline_50_50.py`: `apply_lifeline_50_50()`.
