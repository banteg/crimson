# Creature struct (DAT_0049bf38)

This document tracks the main creature pool used by `crimsonland.exe`.

Pool facts:

- Entry size: `0x98` bytes.
- Pool size: `0x180` entries.
- Base address: `DAT_0049bf38`.

Key helpers:

- `creature_alloc_slot` (`FUN_00428140`) finds a free slot and seeds defaults.
- `creature_spawn` (`FUN_00428240`) spawns a creature and writes position/type/heading.
- `creature_update_all` (`FUN_00426220`) is the primary update loop (movement, targeting, AI, attacks).
- `creatures_none_active` (`FUN_00428210`) scans the pool and returns nonzero when empty.

Field map (medium confidence):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | active (byte) | checked for zero in most loops; set to `1` on spawn, cleared on death. |
| 0x04 | phase seed | randomized on spawn; used to offset orbit/aim timing. |
| 0x08 | state flag | set to `1` in spawners and during AI transitions; exact meaning TBD. |
| 0x09 | collision flag | set when two creatures are within 45 units; drives periodic contact damage ticks. |
| 0x0c | collision timer | decremented when collision flag is set; when it wraps, applies damage. |
| 0x10 | hitbox size | set to `16.0` on spawn; used as a sentinel in contact-damage logic. |
| 0x14 | pos_x | written by `FUN_00428240`; used in distance tests/targeting. |
| 0x18 | pos_y | written by `FUN_00428240`; used in distance tests/targeting. |
| 0x1c | vel_x | computed from heading/speed and passed to `FUN_0041e400`. |
| 0x20 | vel_y | computed from heading/speed and passed to `FUN_0041e400`. |
| 0x24 | health | used as alive check (`> 0`) and perk kill logic. |
| 0x28 | max_health | set from health on spawn; clones use `max_health * 0.25`. |
| 0x2c | heading (radians) | set on spawn; eased toward desired heading each frame. |
| 0x30 | desired heading | computed from target position each frame. |
| 0x34 | size/radius | used in collision tests (`FUN_00420600`) and speed scaling. |
| 0x38 | hit flash timer | decremented each frame; set by `FUN_004207c0` on damage. |
| 0x3c | tint_r | set from spawn color parameter; modified by difficulty scaling. |
| 0x40 | tint_g | set from spawn color parameter; modified by difficulty scaling. |
| 0x44 | tint_b | set from spawn color parameter; modified by difficulty scaling. |
| 0x48 | tint_a | set from spawn color parameter (defaults to `1.0`). |
| 0x4c | force-target flag | set when target is too near/far; snaps target position to player. |
| 0x50 | target_x | derived from player/formation/linked enemy. |
| 0x54 | target_y | derived from player/formation/linked enemy. |
| 0x58 | contact damage | passed to `FUN_00425e50` when touching a player. |
| 0x5c | move speed | per-type speed scalar used to compute velocity. |
| 0x60 | attack cooldown | decremented each frame; gates projectile spawns. |
| 0x64 | reward value (?) | derived from health/speed; reduced by perks. |
| 0x6c | type id | written from spawn param; indexes behavior tables. |
| 0x70 | target player index | toggled based on distance; indexes player arrays. |
| 0x7c | target offset x | used when AI mode links to another creature. |
| 0x80 | target offset y | used when AI mode links to another creature. |
| 0x84 | orbit angle | combined with heading for orbiting AI modes. |
| 0x88 | orbit radius/timer | used by orbiting and tethered AI modes. |
| 0x78 | link index / state timer | used as linked creature index in AI modes; also used as a timer when the `0x80` flag is set. |
| 0x8c | flags | bit tests (`0x4/0x8/0x10/0x40/0x80/0x100/0x400`) gate behaviors. |
| 0x90 | AI mode | selects movement pattern (cases 0/1/3/4/5/6/7/8). |
| 0x94 | anim phase | accumulates to drive sprite timing; wraps at 31 or 15 depending on flags. |

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
- Flags `0x4`, `0x10`, and `0x40` influence sprite selection in `FUN_00418b60`:
  `0x4` selects the short 8‑frame ping‑pong strip, `0x40` forces the long strip
  even when `0x4` is set, and `0x10` offsets the long strip by `+0x20`.

## Spawn template ids (FUN_00430af0)

`FUN_00430af0` uses `param_1` as a spawn template id. It assigns the creature
type id (`&DAT_0049bfa4`) and optional flags (`&DAT_0049bfc4`). The table below
lists the direct assignments found inside the helper.

<!-- spawn-templates:start -->
Generated by `uv run python scripts/gen_spawn_templates.py`.

| Spawn id (param_1) | Type id | Flags (bfc4) | Anim note |
| --- | --- | --- | --- |
| `0x0` | `0` | `0x44` | long strip (`0x40` overrides `0x4`) |
| `0x1` | `4` | `8` |  |
| `0x3` | `3` | `` |  |
| `0x4` | `1` | `` |  |
| `0x5` | `4` | `` |  |
| `0x6` | `2` | `` |  |
| `0x7` | `2` | `4` | short strip (ping‑pong) |
| `0x9` | `2` | `4` | short strip (ping‑pong) |
| `0xa` | `2` | `4` | short strip (ping‑pong) |
| `0xb` | `2` | `4` | short strip (ping‑pong) |
| `0xc` | `2` | `4` | short strip (ping‑pong) |
| `0xe` | `2` | `4` | short strip (ping‑pong) |
| `0x10` | `2` | `4` | short strip (ping‑pong) |
| `0x11` | `1` | `` |  |
| `0x12` | `2` | `` |  |
| `0x14` | `2` | `` |  |
| `0x15` | `2` | `` |  |
| `0x16` | `1` | `` |  |
| `0x17` | `3` | `` |  |
| `0x18` | `2` | `` |  |
| `0x19` | `2` | `` |  |
| `0x1a` | `2` | `` |  |
| `0x1b` | `3` | `` |  |
| `0x1d` | `2` | `` |  |
| `0x1e` | `2` | `` |  |
| `0x1f` | `2` | `` |  |
| `0x20` | `2` | `` |  |
| `0x21` | `2` | `` |  |
| `0x22` | `2` | `` |  |
| `0x23` | `2` | `` |  |
| `0x24` | `2` | `` |  |
| `0x25` | `2` | `` |  |
| `0x26` | `2` | `` |  |
| `0x27` | `2` | `0x400` |  |
| `0x29` | `2` | `` |  |
| `0x2a` | `2` | `` |  |
| `0x2b` | `2` | `` |  |
| `0x2c` | `2` | `` |  |
| `0x2d` | `2` | `` |  |
| `0x2e` | `1` | `` |  |
| `0x2f` | `1` | `` |  |
| `0x30` | `1` | `` |  |
| `0x31` | `1` | `` |  |
| `0x33` | `3` | `` |  |
| `0x34` | `3` | `` |  |
| `0x35` | `4` | `` |  |
| `0x36` | `2` | `` |  |
| `0x37` | `4` | `0x100` |  |
| `0x38` | `3` | `0x80` |  |
| `0x39` | `3` | `0x80` |  |
| `0x3a` | `3` | `0x10` | alt strip (+0x20) |
| `0x3b` | `3` | `` |  |
| `0x3c` | `3` | `0x100` |  |
| `0x3d` | `3` | `` |  |
| `0x3e` | `3` | `` |  |
| `0x40` | `3` | `` |  |
| `0x41` | `0` | `` |  |
| `0x42` | `0` | `` |  |
| `0x43` | `0` | `` |  |

<!-- spawn-templates:end -->

Notes:

- Flags `0x4`, `0x10`, and `0x40` are the only bits with confirmed animation effects.
- Flag `0x8` triggers the split‑on‑death behavior (see `FUN_0041e910`).
- Flag `0x400` calls `FUN_0041f5b0` on death (spawns a bonus entry using two 16‑bit
  values from `&DAT_0049bfb0`).

## Spawn id sources (call sites)

`param_1` is supplied by a mix of scripted spawners and data tables:

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
| 0x08 | heading | passed as `param_3` to `FUN_00430af0`. |
| 0x0c | spawn id | cast to int and passed as `param_1` to `FUN_00430af0`. |
| 0x10 | trigger time | compared against `DAT_00486fd0` (quest clock). |
| 0x14 | count | number of spawns in the group; decremented to 0 after firing. |

Notes:

- `quest_start_selected` (`FUN_0043a790`) chooses a quest builder from the table at
  `DAT_00484730`. The function pointer lives at `&DAT_0048474c`; when null, it
  falls back to `quest_build_fallback` (`FUN_004343e0`) (two entries with spawn id
  `0x40`, counts 10/0x14, trigger times
  500/5000).
- `FUN_00437d70`, `FUN_00438840`, and `FUN_00438940` are examples of quest builders
  that write multiple `DAT_004857a8` entries with varying spawn ids and timings.
