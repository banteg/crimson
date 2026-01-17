# Creature struct (DAT_0049bf38)

This document tracks the main creature pool used by `crimsonland.exe`.

Pool facts:

- Entry size: `0x98` bytes.
- Pool size: `0x180` entries.
- Base address: `DAT_0049bf38`.

Key helpers:

- `creature_alloc_slot` (`FUN_00428140`) finds a free slot and seeds defaults.
- `FUN_00428240` spawns a creature and writes position/type/heading.
- `FUN_00426220` is the primary update loop (movement, targeting, AI, attacks).
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
| 0x8c | flags | bit tests (`0x4/0x8/0x40/0x80/0x100/0x400`) gate behaviors. |
| 0x90 | AI mode | selects movement pattern (cases 0/1/3/4/5/6/7/8). |
| 0x94 | anim phase | accumulates to drive sprite timing; wraps at 31 or 15 depending on flags. |

Related notes:

- See [Detangling notes](detangling.md) for helper naming and other pool context.
- The pool is updated in `FUN_00426220`; use that routine for new field discoveries.
- Animation phase (`0x94`) is incremented by a per-type rate stored at
  `&DAT_0048275c + type_id * 0x44` and wraps at **31** for the primary strip or **15**
  for the short ping‑pong strip. The renderer then selects a frame index for the 8×8
  atlas (see `FUN_00418b60`).
