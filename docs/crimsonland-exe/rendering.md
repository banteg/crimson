---
tags:
  - status-analysis
---

# Rendering pipeline
This page summarizes the primary render paths in `crimsonland.exe`.

## Render dispatcher (game_update_generic_menu)

- If `render_pass_mode` (`0x00487240`) == `0` and `game_state_id` (`0x00487270`) != `5`, it draws terrain only via
  `terrain_render` (`0x004188a0`).

- Otherwise it runs the full gameplay render pass `gameplay_render_world` (`0x00405960`).
- After either branch it applies a fullscreen fade (`screen_fade_alpha`), runs
  `ui_elements_update_and_render`, calls `perk_prompt_update_and_render` (`0x00403550`) (perk prompt), and
  renders the UI cursor.

## Gameplay render pass (gameplay_render_world / 0x00405960)

Order of major passes:

1) `fx_queue_render` (`0x00427920`)
2) `terrain_render` (`0x004188a0`) (terrain/backbuffer blit)
3) `player_render_overlays` (`0x00428390`) for players with
   `player_health` (`0x004908d4`) <= 0

4) `creature_render_all` (`0x00419680`)
5) `player_render_overlays` for players with `player_health` (`0x004908d4`) > 0
6) `projectile_render` (`0x00422c70`)
7) `bonus_render` (`0x004295f0`)
8) `grim_draw_fullscreen_color` fade when `screen_fade_alpha > 0`

Notes:

- `render_overlay_player_index` is used as the player index during the two overlay passes.
- `ui_transition_alpha` (`0x00487278`) is the frame alpha used by multiple render paths.
- `projectile_render` binds both `projectile_texture` (`0x0048f7d4`) and
  `projectile_bullet_texture` (`0x0049bb30`, `bullet_i`) for distinct projectile sprite passes.
- `gameplay_transition_latch` (`0x00487241`) is set on gameplay/Typ-o gameplay
  state entry and cleared when the HUD transition timeline reaches 1.0; while
  set, `gameplay_render_world` avoids forcing `ui_transition_alpha` to 1.0 in
  branch paths that normally suppress transition fades.
- `player_overlay_suppressed_latch` (`0x0048727c`) is an additional hard gate
  for `player_render_overlays` during highscore-return/result-flow transitions.

## HUD render (ui_render_hud / 0x0041aed0)

The in-game HUD render is gated by `demo_mode_active` (`0x0048700d`) and is called from the main
UI pass (`hud_update_and_render`). It binds `ui_wicons` and uses `grim_set_sub_rect` for
weapon icons, along with health/score overlays.

`hud_update_and_render` sets explicit per-mode HUD gates before rendering:

- `hud_show_health_panel`
- `hud_show_weapon_panel`
- `hud_show_xp_panel`
- `hud_show_quest_panel`
- `hud_show_timer_panel`

## Shared tint vectors

Several UI/HUD paths use a shared global RGBA vector passed to
`grim_set_color_ptr`:

- `render_tint_color_r/g/b/a` (`0x004965f8..0x00496604`)
- Alpha (`render_tint_color_a`) is animated in loading, HUD, game-over, and
  quest-results paths while RGB stays white.

High-score card divider rendering uses a second RGBA block:

- `highscore_card_divider_color_r/g/b/a` (`0x004ccca8..0x004cccb4`)
- Seeded from the shared tint vector with a dimmed alpha in
  `ui_text_input_render`, then consumed by `highscore_card_draw_horizontal_divider`
  and `highscore_card_draw_vertical_divider`.

## Terrain generation (terrain_generate / 0x00417b80)

`terrain_generate` renders the terrain texture into a render target and selects
its base texture index from a per-level descriptor.

For the full pipeline (init, procedural stamping, FX decal baking, and final
screen draw), see [Terrain pipeline](terrain.md).

### Screen UVs and quest terrain ids

`terrain_render` (`decomp/1.9/crimsonland/ui_render/terrain_render.cpp`) samples
a screen-sized window of the 1024×1024 terrain texture:

- `u0 = -camera_offset_x / terrain_texture_width`
- `v0 = -camera_offset_y / terrain_texture_height`
- `u1 = u0 + (config_screen_width / terrain_texture_width)`
- `v1 = v0 + (config_screen_height / terrain_texture_height)`

Quest terrain indices are `base/overlay/detail = (0,1,0)`, `(2,3,2)`, `(4,5,4)`,
`(6,7,6)` for tiers 1–4 (quests 1–5; quests 6–10 swap the last two), set by
`quest_meta_init_entry` (`decomp/1.9/crimsonland/quests/quest_meta_init_entry.cpp`)
and mirrored by `terrain_slots_for_quest` (`src/crimson/terrain_slots.py`).

## UI overlays

`player_render_overlays` draws per-player indicators (aim reticles, shields,
weapon indicators). It is gated by `game_state_id` (`0x00487270`) values (not drawn in modal
states like `0x14/0x16`), `ui_transition_alpha` (`0x00487278`) (transition alpha),
and `player_overlay_suppressed_latch` (`0x0048727c`).

The same function also checks `player_overlay_auto_target_line_perk_id` (`0x004c2bcc`) via
`perk_count_get` before drawing the segmented auto-target line overlay toward the
current `player_state.auto_target`. `perks_init_database`
(`decomp/1.9/crimsonland/perks/perks_init_database.cpp`) sets this selector to `0`.

### Player sprite layers

From `decomp/1.9/crimsonland/crimsonland/player_render_overlays.cpp` (a historical
Frida summary, `analysis/frida/player_sprite_trace_summary.json`, agrees):

- Alive (`player_state_table.health > 0`): draws **two** sprite layers (UV frames `0..14` and `+0x10`) with a shadow/outline pass (scaled `~1.02/1.03` and offset) before the main pass; rotations come from `heading` vs `aim_heading`.
- Dead: draws a **single** sprite layer, frame `(int)((1 - death_timer / 16) * 20 + 32)` (`32..52`), or `52` once `death_timer < 0`, also with shadow+main passes.

### Player sprite UV tables (2026-01-26)

`player_render_overlays` uses two UV tables for the trooper sprite:

- Legs: `effect_uv8` (8×8 atlas grid, frames `0–14`, empty `15`)
- Torso: `player_overlay_torso_uv8`, which is **`effect_uv8 + 16`** (frames `16–30`, empty `31`)

This table is not filled separately; it aliases into `effect_uv8`, which is populated by
`effect_uv_tables_init` (`0x0041fed0`), called during `game_startup_init_prelude` (`0x0042b090`).

The legs and torso passes therefore draw paired frames `(0,16) … (14,30)`; the trooper atlas
(`game/trooper.jaz`) has fully empty frames at 15 and 31.

### Recoil / muzzle-flash kick (2026-01-26)

Recoil is driven by `player_state.muzzle_flash_alpha`:

- Decay: `muzzle_flash_alpha = max(0, muzzle_flash_alpha - 2 * frame_dt)`
  (applied in both `player_update` and `player_fire_weapon`).

- Firing adds the weapon spread-heat increment (or the Fire Bullets fallback
  value on that branch). Both player paths clamp to `0.8` at their tail.
  Typ-o's `player_fire_weapon` also clamps the old value to `1.0` before adding
  its increment; this is not a second post-shot cap.

These are separate mode paths. Ordinary gameplay calls `player_update`, whose
weapon-fire logic is inline; it does not call `player_fire_weapon`. Typ-o calls
`player_fire_weapon` instead, after its console/dead-player gates. Each reached
path applies the decay once. See
`decomp/1.9/crimsonland/game/gameplay_update_and_render.cpp` and
`decomp/1.9/crimsonland/typo/typo_gameplay_update_and_render.cpp`.

During `player_render_overlays`, the **torso quad** is offset by a recoil vector computed from aim heading:

- `dir = (cos(aim_heading + π/2), sin(aim_heading + π/2))`
- `offset = dir * (muzzle_flash_alpha * 12.0)`
- the torso quad is drawn at `(camera + pos - size/2) + offset`

The recoil pass uses `player_overlay_torso_uv8` and rotates by `aim_heading`.
The shadow/highlight pass draws a slightly larger quad (`size * 1.03`) and shifts it by `(+1, +1)`.

See also:

- [Sprite atlas cutting](../formats/atlas.md)
- [Creature pool struct](../creatures/struct.md)
- [Projectile struct](../structs/projectile.md)
- [Effects pools](../structs/effects.md)
