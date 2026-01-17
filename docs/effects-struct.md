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

This queue is written by `fx_queue_add` (`FUN_0041e840`) and rendered (then
cleared) by `fx_queue_render` once per frame.

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
- `FUN_00427700` is a small helper that spawns a random `fx_queue_add` entry
  (effect ids `3..7`) with randomized grayscale color and size.
- `fx_queue_add` clamps the queue length to `0x7f` if the caller overflows it.

## Rotated FX queue (`DAT_004aaf3c`)

Queue size: `0x40` entries. Written by `fx_queue_add_rotated` (`FUN_00427840`)
and rendered by `fx_queue_render`.

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

- `fx_queue_render` binds `DAT_0048f7dc` (bodyset atlas) and maps `effect_id`
  through the creature type table: `frame = *(int *)(&DAT_00482764 + effect_id * 0x44)`.
  That offset is the per‑type `corpse frame` (see `docs/creature-struct.md`),
  and the frame is converted to UVs via the 4x atlas tables (`DAT_00491210/14`).
- The rotated queue is drawn in two passes: the first uses half alpha and a
  slightly inflated size (`scale * 1.064`), the second uses full alpha/size.
- `fx_queue_add_rotated` skips enqueuing when `DAT_004871c8 != 0` or the queue is full.

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
| 0x14 | rotation | Used in `effects_render`; updated when `flags & 0x4` using `0x40`. |
| 0x18 | scale | Used in `effects_render`; updated when `flags & 0x8` using `0x44`. |
| 0x1c | half_width | Doubled when queuing the expiry sprite. |
| 0x20 | half_height | Doubled when queuing the expiry sprite. |
| 0x24 | age | Incremented by `dt` in `effects_update`. |
| 0x28 | lifetime | Compared against `age` in `effects_update`. |
| 0x2c | flags | `0x4` updates `rotation` via `0x40`; `0x8` updates `scale` via `0x44`; `0x10` fades alpha; `0x40` draws in the first `effects_render` batch; `0x80` spawns `fx_queue_add` on expiry; `0x100` selects a dimmer expiry alpha. |
| 0x30 | color_r | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x34 | color_g | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x38 | color_b | Initialized to `1.0`; passed into `fx_queue_add`. |
| 0x3c | color_a | Initialized to `1.0`; `0x10` flag drives fade-out. |
| 0x40 | rotation_step | Added into `rotation` when `flags & 0x4`. |
| 0x44 | scale_step | Added into `scale` when `flags & 0x8`. |
| 0x48 | quad vertex data | `effect_spawn` writes four corners (pos + UVs) using `half_width/half_height` and the atlas tables. |

Notes:

- `effect_spawn` fills a 4‑corner quad starting at `0x48`. The position and UV
  components are spaced with a 7‑float stride, leaving three unknown floats
  between the position and UV fields for each corner.
- `effects_render` splits entries by `flags & 0x40`. Both passes build a 2x2
  rotation/scale matrix from `rotation` + `scale` and draw the quad data starting
  at `0x48`.
- `effect_free` (`FUN_0042e080`) clears `flags` to `0` and pushes the entry back
  onto the free list; the flag presets always include bit `0x1` to keep `flags`
  nonzero while active.

Common flag presets (from the template helpers that seed `DAT_004ab1dc`):

| Flags | Bits present | Notes |
| --- | --- | --- |
| `0x19` | `0x1` + `0x8` + `0x10` | Base preset with scale step + alpha fade. |
| `0x1d` | `0x1` + `0x4` + `0x8` + `0x10` | Adds rotation step to the base preset. |
| `0x59` | `0x1` + `0x8` + `0x10` + `0x40` | Base preset rendered in the first batch (`flags & 0x40`). |
| `0x5d` | `0x1` + `0x4` + `0x8` + `0x10` + `0x40` | Rotating variant rendered in the first batch. |
| `0xc9` | `0x1` + `0x8` + `0x40` + `0x80` | First-batch preset that spawns a queue entry on expiry. |
| `0x1cd` | `0x1` + `0x4` + `0x8` + `0x40` + `0x80` + `0x100` | As above, but uses the dim expiry alpha (`0x100`). |

Quad layout (from `effect_spawn` writes):

| Corner | pos offsets | uv offsets | Values |
| --- | --- | --- | --- |
| 0 | `0x48/0x4c` | `0x5c/0x60` | `(-half_w, -half_h)` + `(u0, v0)` |
| 1 | `0x64/0x68` | `0x78/0x7c` | `( half_w, -half_h)` + `(u1, v0)` |
| 2 | `0x80/0x84` | `0x94/0x98` | `( half_w,  half_h)` + `(u1, v1)` |
| 3 | `0xa0/0xa4` | `0xb0/0xb4` | `(-half_w,  half_h)` + `(u0, v1)` |

- `effect_spawn` reads `DAT_004755f0/4` to pick atlas size + frame index, then
  pulls UVs from size-specific tables:
  - `0x10` -> `DAT_004aa4d8/4` with base `_DAT_004755ec`.
  - `0x20` -> `DAT_00491010/14` with base `_DAT_004755e8`.
  - `0x40` -> `DAT_00491210/14` with base `_DAT_004755e4`.
  - `0x80` -> `DAT_00491290/94` with base `_DAT_004755e0`.
- `effect_spawn` copies 15 floats from the template block at `DAT_004ab1bc`
  into offsets `0x0c..0x44` (see template map below).

### Effect template block (`DAT_004ab1bc`)

These globals act as a staging area for `effect_spawn`. They are copied into
the effect entry (offsets `0x0c..0x44`) before the UVs are assigned.

| Template | Entry offset | Meaning |
| --- | --- | --- |
| `DAT_004ab1bc` | 0x0c | vel_x |
| `DAT_004ab1c0` | 0x10 | vel_y |
| `DAT_004ab1c4` | 0x14 | rotation |
| `DAT_004ab1c8` | 0x18 | scale |
| `DAT_004ab1cc` | 0x1c | half_width |
| `DAT_004ab1d0` | 0x20 | half_height |
| `DAT_004ab1d4` | 0x24 | age |
| `DAT_004ab1d8` | 0x28 | lifetime |
| `DAT_004ab1dc` | 0x2c | flags |
| `DAT_004ab1e0` | 0x30 | color_r |
| `DAT_004ab1e4` | 0x34 | color_g |
| `DAT_004ab1e8` | 0x38 | color_b |
| `DAT_004ab1ec` | 0x3c | color_a |
| `DAT_004ab1f0` | 0x40 | rotation_step |
| `DAT_004ab1f4` | 0x44 | scale_step |

### Effect id table (`DAT_004755f0`)

Entry size: `0x08` bytes. Indexed by `effect_id`.

`effect_select_texture` (`FUN_0042e0a0`) reads this table and calls the renderer
with grid sizes `16/8/4/2` depending on the size code (`0x10/0x20/0x40/0x80`).

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | atlas size code | Read by `effect_select_texture`/`effect_spawn`; values `0x10/0x20/0x40/0x80` map to `16/8/4/2` cell atlases. |
| 0x04 | frame index | Read by `effect_select_texture`/`effect_spawn`; selects the atlas frame. |

Known entries (extracted from `crimsonland.exe` at `DAT_004755f0`):

| effect_id | size code | frame |
| --- | --- | --- |
| `0x00` | `0x80` | `0x2` |
| `0x01` | `0x80` | `0x3` |
| `0x02` | `0x20` | `0x0` |
| `0x03` | `0x20` | `0x1` |
| `0x04` | `0x20` | `0x2` |
| `0x05` | `0x20` | `0x3` |
| `0x06` | `0x20` | `0x4` |
| `0x07` | `0x20` | `0x5` |
| `0x08` | `0x20` | `0x8` |
| `0x09` | `0x20` | `0x9` |
| `0x0a` | `0x20` | `0xa` |
| `0x0b` | `0x20` | `0xb` |
| `0x0c` | `0x40` | `0x5` |
| `0x0d` | `0x40` | `0x3` |
| `0x0e` | `0x40` | `0x4` |
| `0x0f` | `0x40` | `0x5` |
| `0x10` | `0x40` | `0x6` |
| `0x11` | `0x40` | `0x7` |
| `0x12` | `0x10` | `0x26` |

### Effect id usage (partial)

| effect_id | Call sites | Notes |
| --- | --- | --- |
| `0` | `bonus_spawn_at`, `FUN_0042ef60`, `FUN_0042f080`, `FUN_0042f3f0`, `FUN_0042f540`, `FUN_0042f6c0`, `FUN_004207c0` | Generic burst/spark effects (used for bonus pickup and explosions). |
| `1` | `bonus_apply` (Reflex Boost/Freeze), `FUN_0042f080`, `FUN_0042f270`, `FUN_0042f330`, `FUN_0042f6c0` | Power-up ring/halo style effects. |
| `7` | `FUN_0042eb10` | Shock/impact burst used by chain-style effects. |
| `8..10` | `FUN_0042ec80` | Randomized variant picks (`iVar3 % 3 + 8`). |
| `0xc` | `FUN_0042f6c0` | Used during large explosion sequences. |
| `0xe` | `FUN_0042ee00` | Four-way burst helper. |
| `0x11` | `FUN_0042f6c0` | Extra burst when difficulty is high. |
| `0x12` | `player_update` (`FUN_004136b0`) | Muzzle flash path when weapon flag `0x1` is set. |

### Effect template helpers (partial)

These helpers primarily configure `DAT_004ab1bc` and then call `effect_spawn`.

| Function | Effect ids | Notes |
| --- | --- | --- |
| `FUN_0042eb10` | `7` | Spawns two bursts with randomized direction/size; used in projectile/chain effects. |
| `FUN_0042ec80` | `8..10` | Picks a random variant (`iVar3 % 3 + 8`); used by freeze/shatter logic. |
| `FUN_0042ee00` | `0xe`, `8..10` | Four-way burst (`0xe`) plus additional `FUN_0042ec80` calls. |
| `FUN_0042ef60` | `0` | Generic burst loop with randomized velocity. |
| `FUN_0042f080` | `1`, `0` | Ring + burst combo used for power-up visuals. |
| `FUN_0042f270` | `1` | Single ring burst. |
| `FUN_0042f330` | `1` | Single ring burst with different color/alpha defaults. |
| `FUN_0042f3f0` | `0` | Radial scatter of bursts (count parameter). |
| `FUN_0042f540` | `0` | Scaled burst loop used for explosions. |
| `FUN_0042f6c0` | `1`, `0x11`, `0`, `0xc` | Large multi-stage explosion effect. |


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
| 0x10 | color_a / lifetime | Initialized to `1.0` on spawn, decremented by `dt`; when it reaches `<= 0` the entry is deactivated. Also passed into render color alpha. |
| 0x14 | rotation | Seeded from `rand`, incremented by `dt * 3.0`, passed into `grim_set_rotation`. |
| 0x18 | pos_x | Written from `param_1[0]`; advanced by `vel_x` each tick. |
| 0x1c | pos_y | Written from `param_1[1]`; advanced by `vel_y` each tick. |
| 0x20 | vel_x | Written from `param_2[0]`; scaled by `DAT_00480840` in update. |
| 0x24 | vel_y | Written from `param_2[1]`; scaled by `DAT_00480840` in update. |
| 0x28 | scale / size | Written from `param_3`; incremented by `dt * 60.0` before render, but not referenced in the current render path. |

Notes:

- Render is gated by `DAT_00480359` and binds `DAT_0048f7ec` (`particles.png`)
  with a fixed 4x atlas UV (`DAT_00491248/4c`), then draws each active entry
  with the per-entry rotation and RGBA.

Common color overrides (callers mutate the RGBA fields after spawning):

| Override | Fields | Notes |
| --- | --- | --- |
| dim spark | `color_r/g/b = 0.5`, `color_a = 0.25` | Used by projectile detonation sparks (`FUN_00420b90`). |
| soft burst | `color_a = 0.37` | Used by radial burst loops (`FUN_00420b90`). |
| mid alpha | `color_a = 0.7` | Used by periodic spark spawns (`FUN_00420b90`). |
