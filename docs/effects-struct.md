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

### Known style ids (particle pool)

| style id | Source | Notes |
| --- | --- | --- |
| `0` | Plasma Rifle (weapon id `0x8`) | Default fast particle from `fx_spawn_particle`. |
| `1` | HR Flamer (weapon id `0x0f`) | `fx_spawn_particle` plus `DAT_00493ee8 = 1`. |
| `2` | Mini-Rocket Swarmers (weapon id `0x10`) | `fx_spawn_particle` plus `DAT_00493ee8 = 2`. |
| `8` | Rainbow Gun (weapon id `0x2a`) | Slow particle (`fx_spawn_particle_slow`). |

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

### Type id behaviors (secondary pool)

| type id | Behavior | Sources |
| --- | --- | --- |
| `1` | Straight projectile; accelerates while speed < ~500; lifetime decays at 1.0x. On hit or timeout, switches to type `3` detonation with base scale `1.0`. | Seeker Rockets (weapon id `0x0c`). |
| `2` | Homing projectile; targets nearest creature and steers toward it (velocity += 800 * dt, capped ~350). Lifetime decays at 0.5x. On hit or timeout, switches to type `3` detonation with base scale `0.35`. | Plasma Shotgun (weapon id `0x0d`), Rocket Minigun (weapon id `0x11`). |
| `4` | Straight projectile; accelerates while speed < ~600; lifetime decays at 1.0x. On hit or timeout, switches to type `3` detonation with base scale `0.25`. | Pulse Gun (weapon id `0x12`). |
| `3` | Detonation state; expands over ~1s, applies radial damage each tick, spawns `fx_queue_add(0x10)` and clears when the timer > 1.0. | Triggered by types `1/2/4` or when their lifetime expires. |

Render notes:

- Base pass sizes in `projectile_render`: type `1` draws `14x14`, type `2` draws `10x10`,
  type `4` draws `8x8` (all from `projs.png`, atlas frame `4,3`).

## FX queue (`DAT_004912b8`)

Entry size: `0x28` bytes. Queue size: `0x80` entries (index `0..0x7f` via `DAT_004aaf18`).

This queue is written by `fx_queue_add` and rendered (then cleared) by
`fx_queue_render` once per frame.

Layout (struct view of the SoA block):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | effect_id | Stored by `fx_queue_add`; passed into `effect_select_texture` in `fx_queue_render`. |
| 0x04 | rotation | Stored by `fx_queue_add`; passed to `grim_set_rotation`. |
| 0x08 | pos_x | Stored from `pos[0]` in `fx_queue_add`. |
| 0x0c | pos_y | Stored from `pos[1]` in `fx_queue_add`. |
| 0x10 | height | Stored from `h` in `fx_queue_add`; used as draw height. |
| 0x14 | width | Stored from `w` in `fx_queue_add`; used as draw width. |
| 0x18 | color_r | Stored from `rgba[0]` in `fx_queue_add`. |
| 0x1c | color_g | Stored from `rgba[1]` in `fx_queue_add`. |
| 0x20 | color_b | Stored from `rgba[2]` in `fx_queue_add`. |
| 0x24 | color_a | Stored from `rgba[3]` in `fx_queue_add`. |

Notes:

- `effect_select_texture` resolves `effect_id` through `DAT_004755f0/4` and sets
  atlas size/frame (`0x10/0x20/0x40/0x80` -> `16/8/4/2` cells).

## Rotated FX queue (`DAT_004aaf3c`)

Queue size: `0x40` entries. Written by `fx_queue_add_rotated` and rendered by
`fx_queue_render`.

Layout (structure-of-arrays):

| Array base | Field | Notes |
| --- | --- | --- |
| `DAT_00490430` | pos_x | Stride 2 floats. |
| `DAT_00490434` | pos_y | Stride 2 floats. |
| `DAT_0049bb38` | color_r | Stride 4 floats. |
| `DAT_0049bb3c` | color_g | Stride 4 floats. |
| `DAT_0049bb40` | color_b | Stride 4 floats. |
| `DAT_0049bb44` | color_a | Stride 4 floats; scaled by view factor in `fx_queue_add_rotated`. |
| `DAT_0049669c` | rotation | Stored from `rotation` in `fx_queue_add_rotated`. |
| `DAT_004906a8` | scale | Stored from `scale` in `fx_queue_add_rotated`. |
| `DAT_0049ba30` | effect_id | Used to index the atlas table in `fx_queue_render`. |

Notes:

- `fx_queue_render` binds `DAT_0048f7dc` and uses `DAT_00482764` to map
  `effect_id` to a 4x atlas frame (`DAT_00491210/14`).
- The rotated queue is drawn in two passes with different alpha scales.

## Effect entries (`DAT_004ab330` pool)

Entry size: `0xbc` bytes (`0x2f` floats). Free list head: `DAT_004c2b30`
with next pointer at offset `0xb8`.

Spawn/update helpers:

- `effect_spawn` (`FUN_0042e120`) allocates an entry and seeds UVs for the
  selected atlas frame.
- `effects_update` (`FUN_0042e710`) advances timers/velocities and frees expired entries.
- `effects_render` (`FUN_0042e820`) draws active entries.

Layout (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | pos_x | Set from `pos[0]` in `effect_spawn`; advanced in `effects_update`. |
| 0x04 | pos_y | Set from `pos[1]` in `effect_spawn`; advanced in `effects_update`. |
| 0x08 | effect_id (byte) | Stored in `effect_spawn`; used when expiring to call `fx_queue_add`. |
| 0x0c | vel_x | `pos_x += vel_x * dt` in `effects_update`. |
| 0x10 | vel_y | `pos_y += vel_y * dt` in `effects_update`. |
| 0x14 | rotation | Passed into `fx_queue_add` on expiry. |
| 0x18 | rotation_2 | Updated when `flags & 0x8` using `0x44`. |
| 0x1c | half_width | Doubled when queuing the expiry sprite. |
| 0x20 | half_height | Doubled when queuing the expiry sprite. |
| 0x24 | age | Incremented by `dt` in `effects_update`. |
| 0x28 | lifetime | Compared against `age` in `effects_update`. |
| 0x2c | flags | `0x4` updates `rotation` via `0x40`; `0x8` updates `rotation_2` via `0x44`; `0x10` fades alpha; `0x80` spawns `fx_queue_add` on expiry; `0x100` selects a dimmer expiry alpha. |
| 0x30 | color_r | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x34 | color_g | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x38 | color_b | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x3c | color_a | Initialized to `1.0`; `0x10` flag drives fade-out. |
| 0x40 | rotation_step | Added into `rotation` when `flags & 0x4`. |
| 0x44 | rotation_step_2 | Added into `rotation_2` when `flags & 0x8`. |
| 0x48 | UV/vertex data | Initialized in `effect_spawn` using atlas tables. |

Notes:

- `effect_spawn` reads `DAT_004755f0/4` to pick atlas size + frame index, then
  pulls UVs from size-specific tables:
  - `0x10` -> `DAT_004aa4d8/4` with base `_DAT_004755ec`.
  - `0x20` -> `DAT_00491010/14` with base `_DAT_004755e8`.
  - `0x40` -> `DAT_00491210/14` with base `_DAT_004755e4`.
  - `0x80` -> `DAT_00491290/94` with base `_DAT_004755e0`.


## Sprite effect pool (`DAT_00496820`)

Entry size: `0x2c` bytes. Pool size: `0x180` entries (looping to `0x49aa20`).

Spawn helper:

- `FUN_0041fbb0` -> `fx_spawn_sprite`

Layout (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | active (byte) | Set to `1` on spawn; cleared when lifetime reaches zero. |
| 0x04 | color_r | Initialized to `1.0` on spawn; passed into render color. |
| 0x08 | color_g | Initialized to `1.0` on spawn; passed into render color. |
| 0x0c | color_b | Initialized to `1.0` on spawn; passed into render color. |
| 0x10 | color_a | Initialized to `1.0` on spawn; passed into render color. |
| 0x14 | rotation / sprite param | Seeded from `rand`, incremented each tick, passed into render helper. |
| 0x18 | pos_x | Written from `param_1[0]`; advanced by `vel_x` each tick. |
| 0x1c | pos_y | Written from `param_1[1]`; advanced by `vel_y` each tick. |
| 0x20 | vel_x | Written from `param_2[0]`; scaled by `DAT_00480840` in update. |
| 0x24 | vel_y | Written from `param_2[1]`; scaled by `DAT_00480840` in update. |
| 0x28 | scale / size | Written from `param_3`; incremented each tick before render. |
