---
tags:
  - status-analysis
---

# Creature AI (creature_update_all)

This page tracks the AI-mode behavior in `creature_update_all` (`FUN_00426220`).

Related fields live in `creature_t`:

- `ai_mode` — selects the behavior case
- `link_index` — linked creature index (formations, escorts) or timer for AI7
- `target_offset_x/target_offset_y` — formation offsets for linked modes
- `orbit_angle` / `orbit_radius` — orbit parameters for some modes

See also: [Creature pool struct](struct.md), [Spawning](spawning.md).

## AI mode behaviors (DAT_0049bfc8 / offset 0x90)

The AI mode selects how the target position (`target_x/target_y`) is computed
inside `creature_update_all`. These notes are medium-confidence.

| Mode | Behavior (inferred) | Evidence |
| --- | --- | --- |
| `0` | Orbit toward player; if far (>800) target = player, else target = player + `cos/sin(phase) * dist * 0.85`. | Uses player index + per-creature phase and distance to pick a target offset. |
| `1` | Tight orbit toward player; same as mode 0 but scale `0.55`. | Same logic with scale 0.55. |
| `2` | Force direct chase; target is forced to player when mode == 2. | `mode == 2` triggers target override to player. |
| `3` | Linked follower; target = linked creature position + per-creature offset. | Uses `link_index` as link; clears mode if target dead. |
| `4` | Linked guard; if link alive, target around player like mode 0; if link dead, mode clears and a damage helper is called. | Clears mode and calls `creature_apply_damage` (`FUN_004207c0`) when link is dead. |
| `5` | Tethered follower; target = link + offset; movement scale shrinks when very close (`dist * 0.015625`). | Computes a local scale from distance to target and clamps it. |
| `6` | Orbit around linked creature; target = link + `cos/sin(angle + heading) * radius`. | Uses per-creature orbit angle/radius fields. |
| `7` | Hold/linger; target = current position while a timer runs. | Uses `link_index` as a countdown (requires flag `0x80`). |
| `8` | Wide orbit toward player; same as mode 0 but scale `0.9`. | Same logic with scale 0.9. |

Notes:

- Linked modes use `link_index` as the linked creature index and `target_offset_x/y` as the per-creature offset.
- Mode `7` interacts with the `0x80` flag (AI7 link/timer); if either guard fails, the mode resets to `0`.

