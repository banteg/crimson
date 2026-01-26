---
tags:
  - status-analysis
---

# Creature struct (creature_pool / DAT_0049bf38)

This document tracks the main creature pool used by `crimsonland.exe`.

Pool facts:

- Entry size: `0x98` bytes.
- Pool size: `0x180` entries.
- Base address: `creature_pool` (`DAT_0049bf38`).

## Struct view (creature_t)

`creature_pool` is typed as `creature_t` (0x98 bytes).

```c
typedef struct creature_t {
    unsigned char active;
    unsigned char _pad0[3];
    float phase_seed;
    unsigned char state_flag;
    unsigned char collision_flag;
    unsigned char _pad1[2];
    float collision_timer;
    float hitbox_size;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float health;
    float max_health;
    float heading;
    float target_heading;
    float size;
    float hit_flash_timer;
    float tint_r;
    float tint_g;
    float tint_b;
    float tint_a;
    int force_target;
    float target_x;
    float target_y;
    float contact_damage;
    float move_speed;
    float attack_cooldown;
    float reward_value;
    unsigned char _pad2[4];
    int type_id;
    int target_player;
    unsigned char _pad3[4];
    int link_index;
    float target_offset_x;
    float target_offset_y;
    float orbit_angle;
    float orbit_radius;
    int flags;
    int ai_mode;
    float anim_phase;
} creature_t;
```

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
| `0x14` | pos_x | `creature_pos_x` | written by `creature_spawn` (`FUN_00428240`); used in distance tests/targeting. |
| `0x18` | pos_y | `creature_pos_y` | written by `creature_spawn` (`FUN_00428240`); used in distance tests/targeting. |
| `0x1c` | vel_x | `creature_vel_x` | computed from heading/speed and passed to `vec2_add_inplace` (`FUN_0041e400`). |
| `0x20` | vel_y | `creature_vel_y` | computed from heading/speed and passed to `vec2_add_inplace` (`FUN_0041e400`). |
| `0x24` | health | `creature_health` | used as alive check (`> 0`) and perk kill logic. |
| `0x28` | max_health | `creature_max_health` | set from health on spawn; clones use `max_health * 0.25`. |
| `0x2c` | heading (radians) | `creature_heading` | set on spawn; eased toward desired heading each frame. |
| `0x30` | desired heading | `creature_target_heading` | computed from target position each frame. |
| `0x34` | size/radius | `creature_size` | used in collision tests (`creatures_apply_radius_damage`, `FUN_00420600`) and speed scaling. |
| `0x38` | hit flash timer | `creature_hit_flash_timer` | decremented each frame; set by `creature_apply_damage` (`FUN_004207c0`) on damage. |
| `0x3c` | tint_r | `creature_tint_r` | set from spawn color parameter; modified by difficulty scaling. |
| `0x40` | tint_g | `creature_tint_g` | set from spawn color parameter; modified by difficulty scaling. |
| `0x44` | tint_b | `creature_tint_b` | set from spawn color parameter; modified by difficulty scaling. |
| `0x48` | tint_a | `creature_tint_a` | set from spawn color parameter (defaults to `1.0`). |
| `0x4c` | force-target flag | `creature_force_target` | set when target is too near/far; snaps target position to player. |
| `0x50` | target_x | `creature_target_x` | derived from player/formation/linked enemy. |
| `0x54` | target_y | `creature_target_y` | derived from player/formation/linked enemy. |
| `0x58` | contact damage | `creature_contact_damage` | Passed to `player_take_damage` (`FUN_00425e50`) on player contact; seeded as `size * 0.0952381` in `FUN_00407611`. |
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

- `creature_spawn_slot_table` — spawn slot entry array (0x20 slots); `owner` points to the owning creature (used for collision and cleared on owner death).
- `creature_spawn_slot_count` — current spawn count (`creature_spawn_slot_table[i].count`).
- `creature_spawn_slot_limit` — max spawns before the slot stops (`creature_spawn_slot_table[i].limit`).
- `creature_spawn_slot_interval` — seconds between spawns (`creature_spawn_slot_table[i].interval_s`).
- `creature_spawn_slot_timer` — countdown timer to the next spawn (`creature_spawn_slot_table[i].timer_s`).
- `creature_spawn_slot_template` — spawn template id passed to `creature_spawn_template` (`creature_spawn_slot_table[i].template_id`).

Survival reward tracking (globals):

- `survival_recent_death_pos_x` / `survival_recent_death_pos_y` — up to 3 recent creature death positions (recorded in `creature_handle_death`).
- `survival_recent_death_count` — increments with deaths (caps at 6) and gates the survival weapon reward check in `survival_update`.
- `survival_reward_handout_enabled` — one-time survival handout gate (cleared after the handout or after 3 death samples).
- `survival_reward_fire_seen` — set when the player fires; blocks the survival reward checks in `survival_update`.
- `survival_reward_damage_seen` — set on player damage; blocks the survival reward checks in `survival_update`.

## See also

- [Creature spawning](spawning.md)
- [Creature AI](ai.md)
- [Creature animations](animations.md)
