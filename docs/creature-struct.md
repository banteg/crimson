---
tags:
  - status-draft
---

# Creature struct (creature_pool / DAT_0049bf38)

This document tracks the main creature pool used by `crimsonland.exe`.

Pool facts:

- Entry size: `0x98` bytes.
- Pool size: `0x180` entries.
- Base address: `creature_pool` (`DAT_0049bf38`).

Key helpers:

- `creature_alloc_slot` (`FUN_00428140`) finds a free slot and seeds defaults.
- `creature_spawn` (`FUN_00428240`) spawns a creature and writes position/type/heading.
- `creature_update_all` (`FUN_00426220`) is the primary update loop (movement, targeting, AI, attacks).
- `creatures_none_active` (`FUN_00428210`) scans the pool and returns nonzero when empty.

Field map (medium confidence):

| Offset | Field | Symbol | Evidence |
| --- | --- | --- | --- |
| `0x00` | active (byte) | `creature_pool` | checked for zero in most loops; set to `1` on spawn, cleared on death. |
| `0x04` | phase seed | `creature_phase_seed` | randomized on spawn; used to offset orbit/aim timing. |
| `0x08` | state flag | `creature_state_flag` | set to `1` in spawners and during AI transitions; exact meaning TBD. |
| `0x09` | collision flag | `creature_collision_flag` | set when two creatures are within 45 units; drives periodic contact damage ticks. |
| `0x0c` | collision timer | `creature_collision_timer` | decremented when collision flag is set; when it wraps, applies damage. |
| `0x10` | hitbox size | `creature_hitbox_size` | set to `16.0` on spawn; used as a sentinel in contact-damage logic. |
| `0x14` | pos_x | `creature_pos_x` | written by `FUN_00428240`; used in distance tests/targeting. |
| `0x18` | pos_y | `creature_pos_y` | written by `FUN_00428240`; used in distance tests/targeting. |
| `0x1c` | vel_x | `creature_vel_x` | computed from heading/speed and passed to `FUN_0041e400`. |
| `0x20` | vel_y | `creature_vel_y` | computed from heading/speed and passed to `FUN_0041e400`. |
| `0x24` | health | `creature_health` | used as alive check (`> 0`) and perk kill logic. |
| `0x28` | max_health | `creature_max_health` | set from health on spawn; clones use `max_health * 0.25`. |
| `0x2c` | heading (radians) | `creature_heading` | set on spawn; eased toward desired heading each frame. |
| `0x30` | desired heading | `creature_target_heading` | computed from target position each frame. |
| `0x34` | size/radius | `creature_size` | used in collision tests (`FUN_00420600`) and speed scaling. |
| `0x38` | hit flash timer | `creature_hit_flash_timer` | decremented each frame; set by `FUN_004207c0` on damage. |
| `0x3c` | tint_r | `creature_tint_r` | set from spawn color parameter; modified by difficulty scaling. |
| `0x40` | tint_g | `creature_tint_g` | set from spawn color parameter; modified by difficulty scaling. |
| `0x44` | tint_b | `creature_tint_b` | set from spawn color parameter; modified by difficulty scaling. |
| `0x48` | tint_a | `creature_tint_a` | set from spawn color parameter (defaults to `1.0`). |
| `0x4c` | force-target flag | `creature_force_target` | set when target is too near/far; snaps target position to player. |
| `0x50` | target_x | `creature_target_x` | derived from player/formation/linked enemy. |
| `0x54` | target_y | `creature_target_y` | derived from player/formation/linked enemy. |
| `0x58` | contact damage | `creature_contact_damage` | Passed to `FUN_00425e50` on player contact; seeded as `size * 0.0952381` in `FUN_00407611`. |
| `0x5c` | move speed | `creature_move_speed` | Per-type speed scalar used to compute velocity; seeded to `0.9..` range in `FUN_00407611`. |
| `0x60` | attack cooldown | `creature_attack_cooldown` | Decremented each frame; gates projectile spawns. |
| `0x64` | reward value | `creature_reward_value` | Seeded from health/contact/speed (`health * 0.4 + contact * 0.8 + speed * 5 + rand(10..19)`), then scaled by `0.8` in the spawner. |
| `0x6c` | type id | `creature_type_id` | written from spawn param; indexes behavior tables. |
| `0x70` | target player index | `creature_target_player` | toggled based on distance; indexes player arrays. |
| `0x78` | link index / state timer | `creature_link_index` | used as linked creature index in AI modes; also used as a timer when the `0x80` flag is set. |
| `0x7c` | target offset x | `creature_target_offset_x` | used when AI mode links to another creature. |
| `0x80` | target offset y | `creature_target_offset_y` | used when AI mode links to another creature. |
| `0x84` | orbit angle | `creature_orbit_angle` | combined with heading for orbiting AI modes. |
| `0x88` | orbit radius/timer | `creature_orbit_radius` | used by orbiting and tethered AI modes. |
| `0x8c` | flags | `creature_flags` | bit tests (`0x4/0x8/0x10/0x40/0x80/0x100/0x400`) gate behaviors. |
| `0x90` | AI mode | `creature_ai_mode` | selects movement pattern (cases 0/1/3/4/5/6/7/8). |
| `0x94` | anim phase | `creature_anim_phase` | accumulates to drive sprite timing; wraps at 31 or 15 depending on flags. |

Global counters:

- `creature_spawned_count` increments on each `creature_alloc_slot` call (total spawns).
- `creature_kill_count` increments on creature death paths (used by the HUD progress ratio).
- `creature_active_count` is recomputed each `creature_update_all` pass.
- `creature_update_tick` is a global tick counter used to throttle some target updates.
- `plaguebearer_infection_count` increments on Plaguebearer contagion kills and caps spread.

Spawn slots (used by `creature_update_all` when `creature_link_index` selects a slot):

- `creature_spawn_slot_owner` — pointer to the owning creature (used for collision and cleared on owner death).
- `creature_spawn_slot_count` — current spawn count.
- `creature_spawn_slot_limit` — max spawns before the slot stops.
- `creature_spawn_slot_interval` — seconds between spawns.
- `creature_spawn_slot_timer` — countdown timer to the next spawn.
- `creature_spawn_slot_template` — spawn template id passed to `creature_spawn_template`.

Survival reward tracking (globals):

- `survival_recent_death_pos_x` / `survival_recent_death_pos_y` — up to 3 recent creature death positions (recorded in `creature_handle_death`).
- `survival_recent_death_count` — increments with deaths (caps at 6) and gates the survival weapon reward check in `survival_update`.
- `survival_reward_handout_enabled` — one-time survival handout gate (cleared after the handout or after 3 death samples).
- `survival_reward_fire_seen` — set when the player fires; blocks the survival reward checks in `survival_update`.
- `survival_reward_damage_seen` — set on player damage; blocks the survival reward checks in `survival_update`.

## AI mode behaviors (DAT_0049bfc8 / offset 0x90)

The AI mode selects how the target position (`target_x/target_y`) is computed
inside `creature_update_all`. These notes are medium-confidence.

| Mode | Behavior (inferred) | Evidence |
| --- | --- | --- |
| `0` | Orbit toward player; if far (>800) target = player, else target = player + `cos/sin(phase) * dist * 0.85`. | Uses player index + per-creature phase (`DAT_0049bf3c`) and distance to pick a target offset. |
| `1` | Tight orbit toward player; same as mode 0 but scale `0.55`. | Same logic with scale 0.55. |
| `2` | Force direct chase; target is forced to player when mode == 2. | `mode == 2` triggers target override to player. |
| `3` | Linked follower; target = linked creature position + per-creature offset (`DAT_0049bfb4/b8`). | Uses `DAT_0049bfb0` as link index; clears mode if target dead. |
| `4` | Linked guard; if link alive, target around player like mode 0; if link dead, mode clears and a damage helper is called. | Clears mode and calls `FUN_004207c0` when link is dead. |
| `5` | Tethered follower; target = link + offset; movement scale shrinks when very close (`dist * 0.015625`). | Computes `local_70` from distance to target and clamps in 0..1 range. |
| `6` | Orbit around linked creature; target = link + `cos/sin(angle + heading) * radius`. | Uses `DAT_0049bfc0` (radius) and `DAT_0049bfbc` (angle). |
| `7` | Hold/linger; target = current position while a timer runs. | Uses `DAT_0049bfc0` as countdown; clears mode when expired. |
| `8` | Wide orbit toward player; same as mode 0 but scale `0.9`. | Same logic with scale 0.9. |

Notes:

- Linked modes use `DAT_0049bfb0` as the linked creature index and `DAT_0049bfb4/b8`
  as the per-creature offset.
- Mode `7` interacts with the `0x80` flag and the `DAT_0049bfb0` link index; if
  either guard fails, the mode resets to `0`.

Related notes:

- See [Detangling notes](detangling.md) for helper naming and other pool context.
- The pool is updated in `creature_update_all`; use that routine for new field discoveries.
- On death, `creature_update_all` queues a rotated sprite via `fx_queue_add_rotated`
  using the creature tint and size. The `effect_id` is usually the creature `type_id`,
  but short-strip creatures (`flags & 0x4` without `0x40`) force `effect_id = 7`
  (likely a generic corpse sprite).
- Animation phase (`0x94`) is incremented by a per-type rate stored at
  `&DAT_0048275c + type_id * 0x44` and wraps at **31** for the primary strip or **15**
  for the short ping‑pong strip. The renderer then selects a frame index for the 8×8
  atlas (see `FUN_00418b60`).
- `creature_update_all` scales the animation step by movement speed, size, and a
  local scale factor (tether/orbit cases), using `rate * speed * dt * (30/size)`
  multiplied by **25** (long strip) or **22** (short strip) before wrapping.
- Flags `0x4` and `0x40` influence sprite selection in `FUN_00418b60`:
  `0x4` selects the short 8‑frame ping‑pong strip and `0x40` forces the long strip
  even when `0x4` is set.
- `FUN_00418b60` computes the short strip frame as
  `frame = base + 0x10 + ping_pong(int(phase) & 0xf)`, where `ping_pong` mirrors
  indices `> 7` to `0xf - idx`. The long strip uses `frame = base + int(phase)`
  (mirrored to `0x1f - frame` when `type_flags & 1` and `frame > 0x0f`), with
  negative phases falling back to `base + 0x0f`.

### Creature flags (partial)

The `creature_flags` bitfield is consulted in `creature_update_all` and related helpers:

- **0x1** — periodic self‑damage tick (`creature_apply_damage` with magnitude `dt * 60`).
- **0x2** — stronger periodic self‑damage tick (`creature_apply_damage` with magnitude `dt * 180`).
- **0x4** — short ping‑pong animation strip (see render notes above).
- **0x10** — ranged attack: when `attack_cooldown <= 0` and target distance > 64,
  spawns projectile type `9` and plays `sfx_shock_fire` (`DAT_004c3f9c`).
- **0x40** — force long animation strip even if `0x4` is set.
- **0x80** — uses `creature_link_index` as a timer that toggles AI mode `7`
  with randomized positive/negative durations.
- **0x100** — ranged attack variant: spawns projectile using the
  `creature_orbit_radius` field as the projectile type id and plays
  `sfx_plasmaminigun_fire` (`DAT_004c3fa0`).

## Creature type table (`creature_type_texture` / `DAT_00482728`)

Stride: `0x44` bytes (`0x11` floats). Indexed by `type_id`.

Field map (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | sprite texture handle | `creature_type_texture`; bound in `creature_render_type` via `grim_bind_texture`. |
| 0x04 | sfx bank A [0] | `creature_type_sfx_a0`; `FUN_004207c0` chooses `uVar3 = rand() & 3` and calls `FUN_0043d260` on `&creature_type_sfx_a0 + (uVar3 + type_id * 0x11) * 4`. |
| 0x08 | sfx bank A [1] | `creature_type_sfx_a1`; same selection as above. |
| 0x0c | sfx bank A [2] | `creature_type_sfx_a2`; same selection as above; also used by chain-kill paths. |
| 0x10 | sfx bank A [3] | `creature_type_sfx_a3`; same selection as above (the 0..3 range proves this slot is live). |
| 0x14 | sfx bank B [0] | `creature_type_sfx_b0`; contact-damage removal path picks `uVar7 = rand() & 1` and calls `FUN_0043d260` on `&creature_type_sfx_b0 + (uVar7 + type_id * 0x11) * 4`. |
| 0x18 | sfx bank B [1] | `creature_type_sfx_b1`; same selection as above (second slot in the 0..1 range). |
| 0x20 | unknown (const 1.0) | Set to `1.0` for every type in the init routine; no reads found in the decompiled output. |
| 0x34 | anim rate | `creature_type_anim_rate`; multiplies animation step in `creature_update_all` (drives `anim phase`). |
| 0x38 | atlas base frame | `creature_type_base_frame`; start frame for the long strip (used with `+0x10` or `+0x20` offsets in `creature_render_type`). |
| 0x3c | corpse frame | `creature_type_corpse_frame`; used by `fx_queue_render` to select the bodyset frame for corpse sprites. |
| 0x40 | anim mirror flag | `creature_type_anim_flags`; when bit `1` is set, the long strip mirrors frames `> 0x0f` in `creature_render_type`. |

Known initial entries (from the reset/init routine that loads creature textures):

| type_id | texture | anim rate | base frame | corpse frame | flags |
| --- | --- | --- | --- | --- | --- |
| `0` | `s_zombie_0047375c` | `1.2` | `0x20` | `0` | `0` |
| `1` | `s_lizard_00473754` | `1.6` | `0x10` | `3` | `1` |
| `2` | `s_alien_00473734` | `1.35` | `0x20` | `4` | `0` |
| `3` | `s_spider_sp1_00473748` | `1.5` | `0x10` | `1` | `1` |
| `4` | `s_spider_sp2_0047373c` | `1.5` | `0x10` | `2` | `1` |
| `5` | `s_trooper_0047372c` | not set in init | not set in init | `7` | not set in init |

Notes:

- No references to offsets `0x1c..0x30` were found in the decompiled output.
  Only offset `0x20` is initialized (to `1.0`), so the remaining fields appear
  unused or reserved in this build.

## Spawn template ids (creature_spawn_template)

`creature_spawn_template` uses `template_id` (aka `param_1`) as a spawn template id. It assigns the
creature type id (`&creature_type_id`, formerly `DAT_0049bfa4`) and optional flags
(`&creature_flags`, formerly `DAT_0049bfc4`). The table below lists the direct
assignments found inside the helper.

<!-- spawn-templates:start -->
Generated by `uv run python scripts/gen_spawn_templates.py`.

| Spawn id (template_id) | Type id | Creature | Flags (creature_flags) | Anim note |
| --- | --- | --- | --- | --- |
| `0x0` | `0` | `zombie` | `0x44` | long strip (0x40 overrides 0x4) |
| `0x1` | `4` | `spider_sp2` | `0x8` |  |
| `0x3` | `3` | `spider_sp1` | `` |  |
| `0x4` | `1` | `lizard` | `` |  |
| `0x5` | `4` | `spider_sp2` | `` |  |
| `0x6` | `2` | `alien` | `` |  |
| `0x7` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x8` | `1` | `lizard` | `0x10` |  |
| `0x9` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xa` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xb` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xc` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xd` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xe` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0xf` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x10` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x11` | `1` | `lizard` | `` |  |
| `0x12` | `2` | `alien` | `` |  |
| `0x13` | `2` | `alien` | `0x4` | short strip (ping-pong) |
| `0x14` | `2` | `alien` | `` |  |
| `0x15` | `2` | `alien` | `` |  |
| `0x16` | `1` | `lizard` | `` |  |
| `0x17` | `3` | `spider_sp1` | `` |  |
| `0x18` | `2` | `alien` | `` |  |
| `0x19` | `2` | `alien` | `` |  |
| `0x1a` | `2` | `alien` | `` |  |
| `0x1b` | `3` | `spider_sp1` | `` |  |
| `0x1c` | `3` | `spider_sp1` | `0x10` |  |
| `0x1d` | `2` | `alien` | `` |  |
| `0x1e` | `2` | `alien` | `` |  |
| `0x1f` | `2` | `alien` | `` |  |
| `0x20` | `2` | `alien` | `` |  |
| `0x21` | `2` | `alien` | `` |  |
| `0x22` | `2` | `alien` | `` |  |
| `0x23` | `2` | `alien` | `` |  |
| `0x24` | `2` | `alien` | `` |  |
| `0x25` | `2` | `alien` | `` |  |
| `0x26` | `2` | `alien` | `` |  |
| `0x27` | `2` | `alien` | `0x400` |  |
| `0x28` | `3` | `spider_sp1` | `0x10` |  |
| `0x29` | `2` | `alien` | `` |  |
| `0x2a` | `2` | `alien` | `` |  |
| `0x2b` | `2` | `alien` | `` |  |
| `0x2c` | `2` | `alien` | `` |  |
| `0x2d` | `2` | `alien` | `` |  |
| `0x2e` | `1` | `lizard` | `` |  |
| `0x2f` | `1` | `lizard` | `` |  |
| `0x30` | `1` | `lizard` | `` |  |
| `0x31` | `1` | `lizard` | `` |  |
| `0x32` | `2` | `alien` | `0x10` |  |
| `0x33` | `3` | `spider_sp1` | `` |  |
| `0x34` | `3` | `spider_sp1` | `` |  |
| `0x35` | `4` | `spider_sp2` | `` |  |
| `0x36` | `2` | `alien` | `` |  |
| `0x37` | `4` | `spider_sp2` | `0x100` |  |
| `0x38` | `3` | `spider_sp1` | `0x80` |  |
| `0x39` | `3` | `spider_sp1` | `0x80` |  |
| `0x3a` | `3` | `spider_sp1` | `0x10` |  |
| `0x3b` | `3` | `spider_sp1` | `` |  |
| `0x3c` | `3` | `spider_sp1` | `0x100` |  |
| `0x3d` | `3` | `spider_sp1` | `` |  |
| `0x3e` | `3` | `spider_sp1` | `` |  |
| `0x40` | `3` | `spider_sp1` | `` |  |
| `0x41` | `0` | `zombie` | `` |  |
| `0x42` | `0` | `zombie` | `` |  |
| `0x43` | `0` | `zombie` | `` |  |

<!-- spawn-templates:end -->

Notes:

- The table is mirrored into `src/crimson/spawn_templates.py` for Python usage.
- Flags `0x4` and `0x40` are the only bits with confirmed animation effects.
- Flag `0x8` triggers the split‑on‑death behavior (see `FUN_0041e910`).
- Flag `0x400` calls `FUN_0041f5b0` on death (spawns a bonus entry using two 16‑bit
  values from `&DAT_0049bfb0`).

## Spawn id sources (call sites)

`template_id` is supplied by a mix of scripted spawners and data tables:

- `FUN_00402ed0`, `FUN_00402fe0`, `FUN_004030f0`, `FUN_00403250`: mode setup
  helpers called from `FUN_00403390` (hard‑coded spawn ids like `0x34`, `0x35`,
  `0x38`, `0x41`, `0x24`, `0x25`).
- `survival_update` (`FUN_00407cd0`): milestone spawns using `0x12`, `0x2b`,
  `0x2c`, `0x35`, `0x38`, `0x3a`, `0x3c`, and `1`.
- Tutorial timeline (`FUN_00408990`): scripted spawns using `0x24`, `0x26`,
  `0x27`, `0x28`, `0x40`.
- Quest/timeline spawner (`quest_spawn_timeline_update`, `FUN_00434250`): pulls spawn ids from the
  table at `DAT_004857a8` (`pfVar4[3]`) with counts in `pfVar4[5]`.
- AI subspawns (`creature_update_all`): periodic spawns using `&DAT_00484fe4 + iVar6 * 0x18`,
  which is seeded for some template ids inside `FUN_00430af0`.

## Quest spawn table (DAT_004857a8)

Quests populate a fixed table at `DAT_004857a8` (entry size `0x18`, count in
`DAT_00482b08`). `quest_spawn_timeline_update` (`FUN_00434250`) walks the table and
spawns entries whose trigger time has elapsed.

Entry layout (dwords):

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | x | base spawn X; if offscreen, the group spreads along Y instead of X. |
| 0x04 | y | base spawn Y. |
| 0x08 | heading | passed as `heading` to `creature_spawn_template`. |
| 0x0c | spawn id | cast to int and passed as `template_id` to `creature_spawn_template`. |
| 0x10 | trigger time | compared against `DAT_00486fd0` (quest clock). |
| 0x14 | count | number of spawns in the group; decremented to 0 after firing. |

Notes:

- `quest_start_selected` (`FUN_0043a790`) chooses a quest builder from the table at
  `DAT_00484730`. The function pointer lives at `&DAT_0048474c`; when null, it
  falls back to `quest_build_fallback` (`FUN_004343e0`) (two entries with spawn id
  `0x40`, counts 10/0x14, trigger times
  500/5000).
- `quest_build_zombie_time` (`0x00437d70`), `quest_build_lizard_raze` (`0x00438840`), and
  `quest_build_surrounded_by_reptiles` (`0x00438940`) are examples of quest builders that write
  multiple `DAT_004857a8` entries with varying spawn ids and timings.
