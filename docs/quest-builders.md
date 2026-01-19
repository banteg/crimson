# Quest builders

This document lists the quest builder pointer assigned to each quest in
`quest_database_init` (`FUN_00439230`). Builder symbols are defined in
`analysis/ghidra/maps/name_map.json`.

Notes:
- `Start Weapon (id)` is `quest_start_weapon_id` (1-based weapon id).
- `Time (ms)` is `quest_meta_time_limit_ms`.
- `Builder` is the named function symbol used for the quest spawn script.

## Quest -> builder table
| Tier | Quest | Title | Start Weapon (id) | Time (ms) | Builder | Address |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | Land Hostile | 1 | 120000 | quest_build_land_hostile | 0x00435bd0 |
| 1 | 2 | Minor Alien Breach | 1 | 120000 | quest_build_minor_alien_breach | 0x00435cc0 |
| 1 | 3 | Target Practice | 1 | 65000 | quest_build_target_practice | 0x00437a00 |
| 1 | 4 | Frontline Assault | 1 | 300000 | quest_build_frontline_assault | 0x00437e10 |
| 1 | 5 | Alien Dens | 1 | 180000 | quest_build_alien_dens | 0x00436720 |
| 1 | 6 | The Random Factor | 1 | 300000 | quest_build_the_random_factor | 0x00436350 |
| 1 | 7 | Spider Wave Syndrome | 1 | 240000 | quest_build_spider_wave_syndrome | 0x00436440 |
| 1 | 8 | Alien Squads | 1 | 180000 | quest_build_alien_squads | 0x00435ea0 |
| 1 | 9 | Nesting Grounds | 1 | 240000 | quest_build_nesting_grounds | 0x004364a0 |
| 1 | 10 | 8-legged Terror | 1 | 240000 | quest_build_8_legged_terror | 0x00436120 |
| 2 | 1 | Everred Pastures | 1 | 300000 | quest_build_everred_pastures | 0x004375a0 |
| 2 | 2 | Spider Spawns | 1 | 300000 | quest_build_spider_spawns | 0x00436d70 |
| 2 | 3 | Arachnoid Farm | 1 | 240000 | quest_build_arachnoid_farm | 0x00436820 |
| 2 | 4 | Two Fronts | 1 | 240000 | quest_build_two_fronts | 0x00436ee0 |
| 2 | 5 | Sweep Stakes | 6 | 35000 | quest_build_sweep_stakes | 0x00437810 |
| 2 | 6 | Evil Zombies At Large | 1 | 180000 | quest_build_evil_zombies_at_large | 0x004374a0 |
| 2 | 7 | Survival Of The Fastest | 5 | 120000 | quest_build_survival_of_the_fastest | 0x00437060 |
| 2 | 8 | Land Of Lizards | 1 | 180000 | quest_build_land_of_lizards | 0x00437ba0 |
| 2 | 9 | Ghost Patrols | 1 | 180000 | quest_build_ghost_patrols | 0x00436200 |
| 2 | 10 | Spideroids | 1 | 360000 | quest_build_spideroids | 0x004373c0 |
| 3 | 1 | The Blighting | 1 | 300000 | quest_build_the_blighting | 0x00438050 |
| 3 | 2 | Lizard Kings | 1 | 180000 | quest_build_lizard_kings | 0x00437710 |
| 3 | 3 | The Killing | 1 | 300000 | quest_build_the_killing | 0x004384a0 |
| 3 | 4 | Hidden Evil | 1 | 300000 | quest_build_hidden_evil | 0x00435a30 |
| 3 | 5 | Surrounded By Reptiles | 1 | 300000 | quest_build_surrounded_by_reptiles | 0x00438940 |
| 3 | 6 | The Lizquidation | 1 | 300000 | quest_build_the_lizquidation | 0x00437c70 |
| 3 | 7 | Spiders Inc. | 11 | 300000 | quest_build_spiders_inc | 0x004390d0 |
| 3 | 8 | Lizard Raze | 1 | 300000 | quest_build_lizard_raze | 0x00438840 |
| 3 | 9 | Deja vu | 6 | 120000 | quest_build_deja_vu | 0x00437920 |
| 3 | 10 | Zombie Masters | 1 | 300000 | quest_build_zombie_masters | 0x004360a0 |
| 4 | 1 | Major Alien Breach | 18 | 300000 | quest_build_major_alien_breach | 0x00437af0 |
| 4 | 2 | Zombie Time | 1 | 300000 | quest_build_zombie_time | 0x00437d70 |
| 4 | 3 | Lizard Zombie Pact | 1 | 300000 | quest_build_lizard_zombie_pact | 0x00438700 |
| 4 | 4 | The Collaboration | 1 | 360000 | quest_build_the_collaboration | 0x00437f30 |
| 4 | 5 | The Massacre | 1 | 300000 | quest_build_the_massacre | 0x004383e0 |
| 4 | 6 | The Unblitzkrieg | 1 | 600000 | quest_build_the_unblitzkrieg | 0x00438a40 |
| 4 | 7 | Gauntlet | 1 | 300000 | quest_build_gauntlet | 0x004369a0 |
| 4 | 8 | Syntax Terror | 1 | 300000 | quest_build_syntax_terror | 0x00436c10 |
| 4 | 9 | The Annihilation | 1 | 300000 | quest_build_the_annihilation | 0x004382c0 |
| 4 | 10 | The End of All | 1 | 480000 | quest_build_the_end_of_all | 0x00438e10 |
| 5 | 1 | The Beating | 1 | 480000 | quest_build_the_beating | 0x00435610 |
| 5 | 2 | The Spanking Of The Dead | 1 | 480000 | quest_build_the_spanking_of_the_dead | 0x004358a0 |
| 5 | 3 | The Fortress | 1 | 480000 | quest_build_the_fortress | 0x004352d0 |
| 5 | 4 | The Gang Wars | 1 | 480000 | quest_build_the_gang_wars | 0x00435120 |
| 5 | 5 | Knee-deep in the Dead | 1 | 480000 | quest_build_knee_deep_in_the_dead | 0x00434f00 |
| 5 | 6 | Cross Fire | 1 | 480000 | quest_build_cross_fire | 0x00435480 |
| 5 | 7 | Army of Three | 1 | 480000 | quest_build_army_of_three | 0x00434ca0 |
| 5 | 8 | Monster Blues | 1 | 480000 | quest_build_monster_blues | 0x00434860 |
| 5 | 9 | Nagolipoli | 1 | 480000 | quest_build_nagolipoli | 0x00434480 |
| 5 | 10 | The Gathering | 1 | 480000 | quest_build_the_gathering | 0x004349c0 |

## Builder notes (known implementations)

The builders below have explicit function bodies in the current Ghidra export.
Spawn ids are numeric and still need creature name mapping.

- `quest_build_fallback` (`0x004343e0`): two spawn entries at x = -50, y = terrain_height * 0.5
  with spawn id `0x40`, trigger times `500` / `5000`, and counts `10` / `0x14`.
- `quest_build_the_random_factor` (`0x00436350`): alternating left/right spawns using spawn id `0x1d`
  at `1500ms` + `10000ms` steps (right side at `t`, left side at `t+200`), counts
  scale with player count. Randomly (when `rand % 5 == 3`) adds a center wave
  using spawn id `0x29` at y = `1088`, count = player count.
- `quest_build_spider_wave_syndrome` (`0x00436440`): repeated left-side spawns using spawn id `0x40`
  from `1500ms`, step `5500ms`, until `100500ms`, count = `player_count * 2 + 6`.
- `quest_build_zombie_time` (`0x00437d70`): paired left/right waves using spawn id `0x41` every
  `8000ms` from `1500ms` to `97500ms`, count `8` per side.
- `quest_build_lizard_raze` (`0x00438840`): paired left/right waves using spawn id `0x2e` every
  `6000ms` from `1500ms` to `91500ms`, count `6` per side, plus three fixed spawns
  (spawn id `0x0c`, time `10000ms`, count `1`) at (x=128, y=256/384/512).
- `quest_build_surrounded_by_reptiles` (`0x00438940`):
  - Phase 1: spawn id `0x0d` pairs at x = 256 and x = 768, times `1000..4200` step `800`,
    y = `256 + 0.2 * local_4` where `local_4` steps by `0x200`.
  - Phase 2: spawn id `0x0d` pairs at y = 256 and y = 768, times `8000..11200` step `800`,
    x = `256 + 0.2 * local_4`.

## Quest spawn scripts

Spawn scripts are captured as code in `src/crimson/quests/` (Tier 1 in
`src/crimson/quests/tier1.py`, Tier 2 in `src/crimson/quests/tier2.py`). Use the
CLI (`crimson quests <level>`) to print the resolved entries for a given quest.

## Open questions

- Map spawn ids to creature types (we still only have numeric ids for quest spawns).
- Confirm heading semantics for Target Practice (current heading is derived from the spawn angle).
