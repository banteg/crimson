---
tags:
  - status-analysis
---

# Creature animations

This page tracks how creatures advance animation phase and select atlas frames.

See also: [Creature pool struct](struct.md), [Atlas notes](../atlas.md).

## Animation phase (creature_anim_phase / offset 0x94)

- `creature_anim_phase` (float) is advanced in `creature_update_all` (`FUN_00426220`) using the per-type
  rate stored in the type table (`DAT_00482728`).
- The phase wraps at **31** for the long strip or **15** for the short ping‑pong strip.

## Strip selection and frame mapping

The renderer (`creature_render_type`, `FUN_00418b60`) selects an atlas frame based on:

- the type table `base_frame`
- the per-creature flags (`creature_flags`)
- the integer part of `anim_phase`
- the creature `heading` (rotation)

Known behaviors (medium confidence):

- Flag `0x4` selects the short 8-frame ping‑pong strip.
- Flag `0x40` forces the long strip even when `0x4` is set.
- For the short strip: `frame = base + 0x10 + ping_pong(int(phase) & 0xf)`,
  where ping‑pong folds 0..15 into 0..7..0.
- For the long strip: `frame = base + int(phase)` with an optional mirror fold when the type table sets the mirror flag.
- If per‑creature flags include `0x10`, the frame offset shifts by `+0x20` (alt strip for some spawns).
- Rotation: `grim_set_rotation(creature_heading - pi/2)`; creatures visually face along their movement heading.

## Shadow/outline pass (fx_detail_0)

When `crimson.cfg` `fx_detail_0` is enabled (`config_fx_detail_flag0`) and the **Monster Vision** perk is *not* active,
`creature_render_type` runs an extra pre-pass that darkens behind each creature sprite:

- alpha is derived from creature tint alpha (`tint_a * 0.4` in the decompile)
- the sprite is slightly upscaled (~`size * 1.07`) and offset down-right before the main draw

## Creature flags related to animation / attacks (partial)

The `creature_flags` bitfield is consulted in `creature_update_all` and related helpers:

- **0x4** — short ping‑pong animation strip.
- **0x10** — ranged attack variant; also selects the `+0x20` strip offset in rendering.
- **0x40** — force long animation strip even if `0x4` is set.

## Creature type table (`creature_type_texture` / `DAT_00482728`)

Stride: `0x44` bytes (`0x11` floats). Indexed by `type_id`.

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
