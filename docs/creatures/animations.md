---
tags:
  - status-analysis
---

# Creature animations

This page tracks how creatures advance animation phase and select atlas frames.

See also: [Creature pool struct](struct.md), [Atlas notes](../formats/atlas.md).

## Animation phase (creature_anim_phase / offset 0x94)

- `creature_anim_phase` (float) is advanced in `creature_update_all` (`0x00426220`) using the per-type
  rate stored in the type table (`creature_type_table`).

- The phase wraps at **31** for the long strip or **15** for the short ping‑pong strip.
- Evidence: `analysis/frida/creature_anim_trace_summary.json` (captured via `scripts/frida/creature_anim_trace.js`).

## Strip selection and frame mapping

The renderer (`creature_render_type`, `0x00418b60`) selects an atlas frame based on:

- the type table `base_frame`
- the per-creature flags (`creature_flags`)
- the integer part of `anim_phase`
- the creature `heading` (rotation)

Frame selection is checked against
[2,640 native PC24 witnesses](https://github.com/banteg/crimson/blob/master/tools/match/evidence/creature-frame-selection-2026-09-11/README.md):

- Flag `0x4` selects the short 8-frame ping‑pong strip.
- Flag `0x40` forces the long strip even when `0x4` is set.
- For the short strip: `frame = base + 0x10 + ping_pong(__ftol(phase + 0.5) % 16)`,
  where ping‑pong folds 0..15 into 0..7..0.
  The remainder is signed for diagnostic negative phases; arithmetic before
  integer conversion follows gameplay PC24 rounding.

- For the long strip (alive, `lifecycle_stage >= 16.0`): `frame = __ftol(anim_phase + 0.5)`.
  - If the type mirror flag is set and `frame > 0x0f`, the index is mirrored: `frame = 0x1f - frame`.
- In the shadow/body long-strip passes, flag `0x10` adds `+0x20` after either
  alive or death-stage selection (an alternate strip for some spawns).
- For the long strip during death staging (`0 <= lifecycle_stage < 16.0`): `frame = __ftol((base_frame + 0x0f) - lifecycle_stage)`
  - This effectively ramps through the 16 death frames as `lifecycle_stage` decays from `~16` to `0`.
- For long-strip corpses (`lifecycle_stage < 0.0`): `frame = base_frame + 0x0f` (static corpse frame).
- Rotation: `grim_set_rotation(creature_heading - pi/2)`; creatures visually face along their movement heading.

## Shadow/outline pass (shadows_enabled)

When `crimson.cfg` `shadows_enabled` is enabled (`config_shadows_enabled`) and the **Monster Vision** perk is *not* active,
`creature_render_type` runs an extra pre-pass that darkens behind each creature sprite:

- alpha is derived from creature tint alpha (`tint_a * 0.4` in the decompile)
- the sprite is slightly upscaled (~`size * 1.07`) and offset down-right before the main draw
- for long-strip corpses (`lifecycle_stage < 0.0`), the shadow alpha decays much faster: `tint_a * 0.4 + lifecycle_stage * 0.5` (clamped to `>= 0`).
- Evidence: `analysis/frida/creature_render_trace_summary.json` (captured via `scripts/frida/creature_render_trace.js`).

Each species finishes **all shadows before any body**, followed by its optional
hit flashes. The species order is zombie, spider_sp1, spider_sp2, alien, lizard.
Body and flash dimensions use actual creature size; the ports no longer clamp
Python bodies to 16–128 pixels or tie their dimensions to atlas resolution.
Both ports preserve this ordering, including zero-alpha shadow submissions.
See the [native pass-order and dimension audit](https://github.com/banteg/crimson/blob/master/tools/match/evidence/creature-pass-order-2026-09-11/README.md).

## Body and shadow colour arithmetic

For positive Energizer time and `max_health < 500`, the body tint blends toward
`(0.5, 0.5, 1, 1)` as `(1 - t) * base + t * target`, with `t` capped at 1.
A negative lifecycle then adds `lifecycle_stage * 0.1` to alpha and clamps the
result to zero. Shadow alpha starts at `tint_a * 0.4`; negative lifecycle adds
`lifecycle_stage * 0.5` for long strips or `* 0.1` for short strips, with the
same lower clamp. Transition alpha is multiplied last in both passes.

The ports round each arithmetic operation at gameplay PC24 and pack each
channel by truncating `channel * 255` and keeping its low byte. Without
Energizer or corpse fading, tint `(0.8, 0.7, 0.6, 0.9)` at transition 0.8 becomes `(204, 178, 153, 183)`.
See the [native colour audit](https://github.com/banteg/crimson/blob/master/tools/match/evidence/creature-render-colors-2026-09-11/README.md)
for exact float words, packed bytes, old-port controls and proof limits.

## Hit flash with violence disabled

When `violence_disabled` is nonzero, each species' body batch is followed by
a white additive flash batch. Active matching creatures with positive
`hit_flash_timer` emit **two identical quads** at their actual size. The alpha
is `min(hit_flash_timer * 5, 1) * transition_alpha`, rounded at PC24 after
each multiplication. Grim2D truncates `alpha * 255` when packing the color.
The pass restores normal alpha blending afterward.

The flash uses the same ping-pong frames as the body. For long strips, the
shock offset applies only while `lifecycle_stage >= 16`; dying shock creatures
therefore use a different frame in this pass. Stages below `-10` are retired
by the preceding body pass and do not flash.

`creature_apply_damage` sets the timer to `0.2f`, including zero damage and
corpse hits. The active-creature update subtracts `frame_dt` while the timer
is positive, before the Freeze branch, and allows it to cross below zero.
Spawn allocation clears it. Both ports implement the flash; Zig also restores
the timer from existing replay slot residue. See the
[native lifetime and draw audit](https://github.com/banteg/crimson/blob/master/tools/match/evidence/creature-hit-flash-2026-09-11/README.md).

## Creature flags related to animation / attacks (partial)

The `creature_flags` bitfield is consulted in `creature_update_all` and related helpers:

- **0x4** — short ping‑pong animation strip.
- **0x10** — ranged attack variant; also selects the `+0x20` strip offset in rendering.
- **0x40** — force long animation strip even if `0x4` is set.

## Creature type table (`creature_type_texture` / `creature_type_table`)

Stride: `0x44` bytes (`0x11` floats). Indexed by `type_id`.

`data_map` now labels the entry bases:

- `creature_type_table[0]` (`zombie`) at `0x00482728`
- `creature_type_lizard` at `0x0048276c`
- `creature_type_alien` at `0x004827b0`
- `creature_type_spider_sp1` at `0x004827f4`
- `creature_type_spider_sp2` at `0x00482838`
- `creature_type_trooper` at `0x0048287c`

Field map (partial):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | sprite texture handle | bound in `creature_render_type` via `grim_bind_texture`. |
| 0x04 | sfx bank A [0] | `creature_apply_damage` chooses `rand() & 3` and plays a per-type sound. |
| 0x08 | sfx bank A [1] | same selection as above. |
| 0x0c | sfx bank A [2] | same selection as above; also used by chain-kill paths. |
| 0x10 | sfx bank A [3] | same selection as above (0..3 range proves this slot is live). |
| 0x14 | sfx bank B [0] | contact-damage removal path picks `rand() & 1` and plays a per-type sound. |
| 0x18 | sfx bank B [1] | same selection as above (second slot in the 0..1 range). |
| 0x20 | unknown (const 1.0) | set to `1.0` for every type in the init routine; no reads found in decompiled output. |
| 0x34 | anim rate | multiplies animation step in `creature_update_all`. |
| 0x38 | atlas base frame | start frame for the long strip (used with `+0x10` / `+0x20` offsets in `creature_render_type`). |
| 0x3c | corpse frame | used by corpse sprite paths. |
| 0x40 | anim mirror flag | when set, the long strip mirrors frames `> 0x0f` in `creature_render_type`. |

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
  Only offset `0x20` is initialized (to `1.0`), so the remaining fields appear unused or reserved in this build.
