# Effects pools

This page tracks the smaller effect pools used for weapon and perk visuals.

## Particle pool (`DAT_00493eb8`)

Entry size: `0x38` bytes. Pool size: `0x80` entries (looping to `0x495ab8`).

Spawn helpers:

- `FUN_00420130` -> `fx_spawn_particle` (fast variant, speed ~90)
- `FUN_00420240` -> `fx_spawn_particle_slow` (slow variant, speed ~30)

Layout (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | active (byte) | Set to `1` on spawn; cleared by update/render when expired. |
| 0x01 | render flag | Set to `1` on spawn; referenced in render loops. |
| 0x04 | pos_x | Written from `*param_1` on spawn. |
| 0x08 | pos_y | Written from `param_1[1]` on spawn. |
| 0x0c | vel_x | `cos(angle) * 90` or `*30` on spawn. |
| 0x10 | vel_y | `sin(angle) * 90` or `*30` on spawn. |
| 0x14 | scale_x | Initialized to `1.0` on spawn. |
| 0x18 | scale_y | Initialized to `1.0` on spawn. |
| 0x1c | scale_z | Initialized to `1.0` on spawn. |
| 0x20 | age / timer | Zeroed on spawn. |
| 0x24 | intensity | `param_4` (fast) or `1.0` (slow). |
| 0x28 | angle | Written from `param_2` on spawn. |
| 0x2c | spin | Random `rand % 0x274 * 0.01`. |
| 0x30 | style id | Set to `0`, `1`, `2`, or `8` at callsites. |
| 0x34 | target id | Set to `-1` in slow variant. |

## Secondary projectile pool (`DAT_00495ad8`)

Entry size: `0x2c` bytes. Pool size: `0x40` entries (looping to `0x4965d8`).

Spawn helper:

- `FUN_00420360` -> `fx_spawn_secondary_projectile`

Layout (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | active (byte) | Set to `1` on spawn; cleared in `projectile_update`. |
| 0x04 | angle | Set from `param_2`. |
| 0x08 | speed | Initialized to `2.0` on spawn. |
| 0x0c | pos_x | Written from `*param_1` on spawn. |
| 0x10 | pos_y | Written from `param_1[1]` on spawn. |
| 0x14 | vel_x | `cos(angle - PI/2) * 90` (or `*190` for type `2`). |
| 0x18 | vel_y | `sin(angle - PI/2) * 90` (or `*190` for type `2`). |
| 0x1c | type id | Spawn parameter; branches in `projectile_update`. |
| 0x20 | lifetime | Zeroed on spawn; decremented in update. |
| 0x24 | target id | Set to nearest creature when `type_id == 2`. |

`projectile_update` (`FUN_00420b90`) advances and damages creatures for this pool, and the render path
in the same function draws the sprite variants based on `type id`.

