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
- Historical evidence: `analysis/frida/creature_anim_trace_summary.json` (a Frida trace from before the
  tooling was retired); the recovered `creature_update_all` source is authoritative.

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
- Historical evidence: `analysis/frida/creature_render_trace_summary.json` (a Frida trace from before the
  tooling was retired); the recovered `creature_render_type` source is authoritative.

Each species finishes **all shadows before any body**, followed by its optional
hit flashes. The species order is zombie, spider_sp1, spider_sp2, alien, lizard.
Body and flash dimensions use actual creature size; the Python port no longer
clamps bodies to 16–128 pixels or ties their dimensions to atlas resolution.
It preserves this ordering, including zero-alpha shadow submissions.
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
Spawn allocation clears it. The Python port implements the flash. See the
[native lifetime and draw audit](https://github.com/banteg/crimson/blob/master/tools/match/evidence/creature-hit-flash-2026-09-11/README.md).

## Creature flags

`creature_t.flags` holds `creature_flags_t` bits
(`tools/match/include/crimsonland_gameplay.h`):

| Bit | Name | Behavior |
| --- | --- | --- |
| `0x01` | `CREATURE_FLAG_SELF_DAMAGE_TICK` | `creature_update_all` applies `60 * dt` damage per tick; `creature_render_all` draws a red overlay. |
| `0x02` | `CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG` | Same tick at `180 * dt` (checked before `0x01`). |
| `0x04` | `CREATURE_FLAG_ANIM_PING_PONG` | Short 8-frame ping‑pong animation strip. |
| `0x08` | `CREATURE_FLAG_SPLIT_ON_DEATH` | `creature_handle_death` clones the creature into split children while `size > 35`. |
| `0x10` | `CREATURE_FLAG_RANGED_ATTACK_SHOCK` | Fires `PROJECTILE_TYPE_PLASMA_RIFLE` with the shock sound (cooldown `+1.0`); hits spawn an extra effect; selects the `+0x20` strip offset in rendering. |
| `0x40` | `CREATURE_FLAG_ANIM_LONG_STRIP` | Forces the long animation strip even if `0x4` is set. |
| `0x80` | `CREATURE_FLAG_AI7_LINK_TIMER` | `link_index` counts up as a millisecond timer that drives the hold-timer AI mode. |
| `0x100` | `CREATURE_FLAG_RANGED_ATTACK_VARIANT` | Fires the projectile type stored in `orbit_radius` (`creature_orbit_radius_t`); cooldown `rand(0..3) * 0.1 + orbit_angle`. |
| `0x400` | `CREATURE_FLAG_BONUS_ON_DEATH` | `creature_handle_death` drops the bonus in `bonus_args` (overlaying `link_index`). |

## Creature type table (`creature_type_texture` / `creature_type_table`)

Stride: `0x44` bytes (`0x11` floats). Indexed by `type_id`.

`data_map` now labels the entry bases:

- `creature_type_table[0]` (`zombie`) at `0x00482728`
- `creature_type_lizard` at `0x0048276c`
- `creature_type_alien` at `0x004827b0`
- `creature_type_spider_sp1` at `0x004827f4`
- `creature_type_spider_sp2` at `0x00482838`
- `creature_type_trooper` at `0x0048287c`

Field map (`creature_type_t`, `third_party/headers/crimsonland_types.h`):

| Offset | Field | Evidence |
| --- | --- | --- |
| 0x00 | sprite texture handle | bound in `creature_render_type` via `grim_bind_texture`. |
| 0x04 | sfx bank A [0] | `creature_apply_damage` chooses `rand() & 3` and plays a per-type sound. |
| 0x08 | sfx bank A [1] | same selection as above. |
| 0x0c | sfx bank A [2] | same selection as above; also used by chain-kill paths. |
| 0x10 | sfx bank A [3] | same selection as above (0..3 range proves this slot is live). |
| 0x14 | sfx bank B [0] | contact-damage removal path picks `rand() & 1` and plays a per-type sound. |
| 0x18 | sfx bank B [1] | same selection as above (second slot in the 0..1 range). |
| 0x1c | padding | `_pad0`; never accessed. |
| 0x20 | `unused_value` | Write-only: set to `1.0` for the five animated types in `gameplay_reset_state`; never read. |
| 0x24 | padding | `_pad1[0x10]` (`0x24..0x33`); never accessed. |
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

- Offsets `0x1c` and `0x24..0x33` are padding in `creature_type_t`; `0x20`
  (`unused_value`) is written but never read.
- `gameplay_reset_state` (`decomp/1.9/crimsonland/gameplay/gameplay_reset_state.cpp`)
  sets the trooper's texture, `sfx_bank_a[0..2]`, and `corpse_frame = 7` only;
  its `anim_rate`, `base_frame`, and `anim_flags` stay zero.
