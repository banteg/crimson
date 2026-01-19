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

## Tier 1 spawn scripts (1.x)

Conventions:
- Entries use the quest spawn table layout: `x`, `y`, `heading`, `spawn_id`, `trigger_ms`, `count`.
- If `heading` is not listed, it is `0`.
- `width`/`height` refer to `terrain_texture_width` / `terrain_texture_height`.

### 1.1 Land Hostile (`quest_build_land_hostile`, spawn id 38)

- Entry 0: `x = width / 2`, `y = height + 64`, `t = 500`, `count = 1`.
- Entry 1: `x = -64`, `y = 1088`, `t = 2500`, `count = 2`.
- Entry 2: `x = -64`, `y = -64`, `t = 6500`, `count = 3`.
- Entry 3: `x = 1088`, `y = -64`, `t = 11500`, `count = 4`.

### 1.2 Minor Alien Breach (`quest_build_minor_alien_breach`, spawn ids 38/41)

- Entry 0: `x = 256`, `y = 256`, `t = 1000`, `count = 2` (id 38).
- Entry 1: `x = 256`, `y = 128`, `t = 1700`, `count = 2` (id 38).
- Loop: for `i = 2..17`, `t = 3600 * (i - 2)`:
  - `x = width + 64`, `y = height / 2`, id 38, `count = 1`.
  - if `i >= 7`, add `x = width + 64`, `y = height / 2 - 256`, id 38, `count = 1`.
  - if `i >= 11`, add `x = -64`, `y = height / 2 + 256`, id 38, `count = 1`.
- Special: at `i = 13` (`t = 39600`) add `x = width / 2`, `y = height + 64`, id 41, `count = 1`.

### 1.3 Target Practice (`quest_build_target_practice`, spawn id 54)

- 30 spawns around `(512, 512)` at random polar positions.
- Radius: `32 * (2..9)` (64..288), random angle per spawn.
- `heading = atan2(y - 512, x - 512) - pi/2`.
- Trigger schedule: starts at `2000ms`; step decreases by `50ms` each spawn with a
  floor of `1100ms`. Loop ends when the step would drop to `500ms`.

### 1.4 Frontline Assault (`quest_build_frontline_assault`, spawn ids 38/26/41)

- Main loop `i = 2..21` (20 waves).
- Base spawn: `x = width / 2`, `y = 1088`, `count = 1`, `t = i * step - 5000`.
  - id 38 for `i < 5` and `i >= 10`.
  - id 26 for `i = 5..9`.
- `step` starts at `2500ms` and decreases by `50ms` each wave, floored at `1800ms`.
- Extra spawns:
  - if `i >= 5`: `x = -64`, `y = -64`, id 38, same `t`, `count = 1`.
  - if `i >= 11`: `x = 1088`, `y = -64`, id 38, same `t`, `count = 1`.
  - if `i == 10`: add `x = 1088`, `y = 512` and `x = -64`, `y = 512`, id 41,
    `t = (step * 5 - 2500) * 2` (same as base `t` for `i = 10`), `count = 1` each.

### 1.5 Alien Dens (`quest_build_alien_dens`, spawn id 8)

- Entry 0: `x = 256`, `y = 256`, `t = 1500`, `count = 1`.
- Entry 1: `x = 768`, `y = 768`, `t = 1500`, `count = 1`.
- Entry 2: `x = 512`, `y = 512`, `t = 23500`, `count = player_count`.
- Entry 3: `x = 256`, `y = 768`, `t = 38500`, `count = 1`.
- Entry 4: `x = 768`, `y = 256`, `t = 38500`, `count = 1`.

### 1.6 The Random Factor (`quest_build_the_random_factor`, spawn ids 29/41)

- Repeating pair every `10000ms` from `t = 1500` up to `< 101500`:
  - `x = width + 64`, `y = height / 2`, id 29, `count = player_count * 2 + 4`.
  - `x = -64`, `y = height / 2`, id 29, `t + 200`, `count = 6`.
- Randomly (`rand % 5 == 3`), adds a center-top wave:
  - `x = width / 2`, `y = 1088`, id 41, `t`, `count = player_count`.

### 1.7 Spider Wave Syndrome (`quest_build_spider_wave_syndrome`, spawn id 64)

- Repeated left-side spawns: `x = -64`, `y = height / 2`.
- Times `1500..100500` step `5500`.
- `count = player_count * 2 + 6`.

### 1.8 Alien Squads (`quest_build_alien_squads`, spawn ids 18/38)

- Initial spawns (id 18, `count = 1`):
  - `(-256, 256)` at `1500`.
  - `(-256, 768)` at `2500`.
  - `(768, -256)` at `5500`.
  - `(768, 1280)` at `8500`.
  - `(1280, 1280)` at `14500`.
  - `(1280, 768)` at `18500`.
  - `(-256, 256)` at `25000`.
  - `(-256, 768)` at `30000`.
- Loop (id 38, `count = 1`), starting at `t = 36200` and stepping `1800` until `< 83000`:
  - `(-64, -64)` at `t - 400`.
  - `(1088, 1088)` at `t`.

### 1.9 Nesting Grounds (`quest_build_nesting_grounds`, spawn ids 29/9/8/30/31)

- Entry 0: `x = width / 2`, `y = height + 64`, id 29, `t = 1500`, `count = player_count * 2 + 6`.
- Entry 1: `(256, 256)`, id 9, `t = 8000`, `count = 1`.
- Entry 2: `(512, 512)`, id 9, `t = 13000`, `count = 1`.
- Entry 3: `(768, 768)`, id 9, `t = 18000`, `count = 1`.
- Entry 4: `x = width / 2`, `y = height + 64`, id 29, `t = 25000`, `count = player_count * 2 + 6`.
- Entry 5: `x = width / 2`, `y = height + 64`, id 29, `t = 39000`, `count = player_count * 3 + 3`.
- Entry 6: `(384, 512)`, id 9, `t = 41100`, `count = 1`.
- Entry 7: `(640, 512)`, id 9, `t = 42100`, `count = 1`.
- Entry 8: `(512, 640)`, id 9, `t = 43100`, `count = 1`.
- Entry 9: `(512, 512)`, id 8, `t = 44100`, `count = 1`.
- Entry 10: `x = width / 2`, `y = height + 64`, id 30, `t = 50000`, `count = player_count * 2 + 5`.
- Entry 11: `x = width / 2`, `y = height + 64`, id 31, `t = 55000`, `count = player_count * 2 + 2`.

### 1.10 8-legged Terror (`quest_build_8_legged_terror`, spawn ids 58/61)

- Entry 0: `x = width - 256`, `y = width / 2`, id 58, `t = 1000`, `count = 1`.
- Loop: `t = 6000.. < 36800` step `2200` (14 waves), id 61:
  - `(-25, -25)`, `count = player_count`.
  - `(1049, -25)`, `count = 1`.
  - `(-25, 1049)`, `count = player_count`.
  - `(1049, 1049)`, `count = 1`.

## Open questions

- Map spawn ids to creature types (we still only have numeric ids for quest spawns).
- Confirm heading semantics for Target Practice (current heading is derived from the spawn angle).
