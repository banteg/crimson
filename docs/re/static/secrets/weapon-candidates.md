---
tags:
  - status-analysis
---

# Secret weapon candidates

This page lists named weapons that standard quest progression never unlocks,
and what the 1.9.93 executable does with them. Weapon ids are 1-based; see the
[weapon ID map](../reference/weapon-id-map.md). Player-facing summary:
[secret weapons](../../../mechanics/secret-weapons.md).

## Quest unlock table

`quest_database_init` (`decomp/1.9/crimsonland/quests/quest_database_init.cpp`)
registers each quest through `quest_meta_init_entry`
(`decomp/1.9/crimsonland/quests/quest_meta_init_entry.cpp`), which resets
`unlock_weapon_id = 0` and `unlock_perk_id = perk_id_antiperk`. The function's
tail then assigns `quest_meta_table[i].unlock_weapon_id` for all 50 quests
(`quest_meta_table` stride `0x2c`). Quests not listed below store `0`
(no weapon).

| Index | Quest | Unlocks |
| --- | --- | --- |
| 0 | 1.1 Land Hostile | 2 Assault Rifle |
| 1 | 1.2 Minor Alien Breach | 3 Shotgun |
| 3 | 1.4 Frontline Assault | 8 Flamethrower |
| 5 | 1.6 The Random Factor | 5 Submachine Gun |
| 7 | 1.8 Alien Squads | 6 Gauss Gun |
| 9 | 1.10 8-legged Terror | 12 Rocket Launcher |
| 11 | 2.2 Spider Spawns | 9 Plasma Rifle |
| 13 | 2.4 Two Fronts | 21 Ion Rifle |
| 15 | 2.6 Evil Zombies At Large | 7 Mean Minigun |
| 17 | 2.8 Land Of Lizards | 4 Sawed-off Shotgun |
| 19 | 2.10 Spideroids | 11 Plasma Minigun |
| 21 | 3.2 Lizard Kings | 10 Multi-Plasma |
| 23 | 3.4 Hidden Evil | 13 Seeker Rockets |
| 25 | 3.6 The Lizquidation | 15 Blow Torch |
| 27 | 3.8 Lizard Raze | 18 Rocket Minigun |
| 29 | 3.10 Zombie Masters | 20 Jackhammer |
| 31 | 4.2 Zombie Time | 19 Pulse Gun |
| 33 | 4.4 The Collaboration | 14 Plasma Shotgun |
| 35 | 4.6 The Unblitzkrieg | 17 Mini-Rocket Swarmers |
| 37 | 4.8 Syntax Terror | 22 Ion Minigun |
| 39 | 4.10 The End of All | 23 Ion Cannon |
| 40 | 5.1 The Beating | 31 Ion Shotgun |
| 43 | 5.4 The Gang Wars | 30 Gauss Shotgun |
| 49 | 5.10 The Gathering | 28 Plasma Cannon |

Start weapons (`start_weapon_id`) are Pistol for every quest except Sweep
Stakes and Deja vu (6 Gauss Gun), Survival Of The Fastest (5 Submachine Gun),
Spiders Inc. (11 Plasma Minigun), and Major Alien Breach (18 Rocket Minigun).

## Availability (`weapon_refresh_available`)

`decomp/1.9/crimsonland/weapons/weapon_refresh_available.c` is the only code
that sets `weapon_table[].unlocked`:

- clears all 64 flags, then marks Pistol (1) available;
- marks `quest_meta_table[i].unlock_weapon_id` for `i < quest_unlock_index`
  (capped at 50);
- in Survival (`config_game_mode == GAME_MODE_SURVIVAL`), also marks Assault
  Rifle (2), Shotgun (3), and Submachine Gun (5);
- in the full version, marks Splitter Gun (29) when
  `quest_unlock_index_hardcore >= 40`, i.e. after hardcore 4.10 *The End of All*;
  the demo forces `quest_unlock_index_hardcore = 0`;
- always clears entry 0.

Weapon drops and the Random Weapon perk go through
`weapon_pick_random_available` (`decomp/1.9/crimsonland/weapons/weapon_pick_random_available.cpp`),
which rolls ids `1..33` and rejects entries that are not unlocked. Ids 41+ can
never come from this pool. Other grants are fixed ids: quest and demo start
weapons, Rush (Assault Rifle), Typ-o-Shooter (Shotgun), the tutorial and
spawn-template weapon bonuses (Submachine Gun), and the two Survival handouts.

## Candidates

Named weapons outside the quest unlock table (Pistol excluded). Stats from
`decomp/1.9/crimsonland/weapons/weapon_table_init.cpp`; ids 34-40 and 46-49
are unused slots.

| ID | Name | Clip | Cooldown | Reload | Notes | Acquisition |
| -- | -- | -- | -- | -- | -- | -- |
| 16 | HR Flamer | 30 | 0.0085s | 1.80s | Flag 0x8. | none |
| 24 | Shrinkifier 5k | 8 | 0.21s | 1.22s | Damage 0.0x. Flag 0x8. | Survival handout |
| 25 | Blade Gun | 6 | 0.35s | 3.50s | Damage 11.0x. Projectile speed 20. Flag 0x8. | Survival handout |
| 26 | Spider Plasma | 5 | 0.20s | 1.20s | Damage 0.5x. Projectile speed 10. Flag 0x8. | none |
| 27 | Evil Scythe | 3 | 1.00s | 3.00s | Spread heat 0.68. | none |
| 29 | Splitter Gun | 6 | 0.70s | 2.20s | Damage 6.0x. Projectile speed 30. | hardcore progression |
| 32 | Flameburst | 60 | 0.02s | 3.00s | - | none |
| 33 | RayGun | 12 | 0.70s | 2.00s | - | none |
| 41 | Plague Sphreader Gun | 5 | 0.20s | 1.20s | Damage 0.0x. Projectile speed 15. Flag 0x8. | none |
| 42 | Bubblegun | 15 | 0.16s | 1.20s | Flag 0x8. | none |
| 43 | Rainbow Gun | 10 | 0.20s | 1.20s | Projectile speed 10. Flag 0x8. | none |
| 44 | Grim Weapon | 3 | 0.50s | 1.20s | - | none |
| 45 | Fire bullets | 112 | 0.14s | 1.20s | Damage 0.25x. Projectile speed 60. Flag 0x1. | Fire Bullets bonus stats |
| 50 | Transmutator | 50 | 0.04s | 5.00s | Flag 0x9. | none |
| 51 | Blaster R-300 | 20 | 0.08s | 2.00s | Flag 0x9. | none |
| 52 | Lighting Rifle | 500 | 4.00s | 8.00s | Flag 0x8. | none |
| 53 | Nuke Launcher | 1 | 4.00s | 8.00s | Flag 0x8. | none |

Notes:

- Shrinkifier 5k and Blade Gun are run-scoped grants from `survival_update`;
  see [Survival weapon handouts](survival-weapon-handouts.md).
- Splitter Gun is the only persistent secret unlock (see the availability list
  above).
- Fire bullets (45) is the stats row for the Fire Bullets bonus, not an
  obtainable weapon: `PROJECTILE_TYPE_FIRE_BULLETS` is `0x2d`, so
  `projectile_spawn` and `projectile_update` read its projectile speed and damage
  scale, and the bonus fire path reads its `shot_cooldown` and `spread_heat`
  (`fire_bullets_fallback_shot_cooldown` at `0x004d9040` and
  `fire_bullets_fallback_spread_heat` at `0x004d9048` are those fields).
- The remaining candidates have no acquisition path in 1.9.93.
