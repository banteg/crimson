---
tags:
  - status-analysis
---

# Rendering pipeline
This page summarizes the primary render paths in `crimsonland.exe`.

## Render dispatcher (FUN_00406af0)

- If `render_pass_mode` (`DAT_00487240`) == `0` and `game_state_id` (`DAT_00487270`) != `5`, it draws terrain only via
  `terrain_render` (`FUN_004188a0`).

- Otherwise it runs the full gameplay render pass `gameplay_render_world` (`FUN_00405960`).
- After either branch it applies a fullscreen fade (`DAT_00487264`), runs
  `ui_elements_update_and_render`, calls `perk_prompt_update_and_render` (`FUN_00403550`) (perk prompt), and
  renders the UI cursor.

## Gameplay render pass (gameplay_render_world / FUN_00405960)

Order of major passes:

1) `fx_queue_render` (`FUN_00427920`)
2) `terrain_render` (`FUN_004188a0`) (terrain/backbuffer blit)
3) `player_render_overlays` (`FUN_00428390`) for players with
   `player_health` (`DAT_004908d4`) <= 0

4) `creature_render_all` (`FUN_00419680`)
5) `player_render_overlays` for players with `player_health` (`DAT_004908d4`) > 0
6) `projectile_render` (`FUN_00422c70`)
7) `bonus_render` (`FUN_004295f0`)
8) `grim_draw_fullscreen_color` fade when `DAT_00487264 > 0`

Notes:

- `DAT_004aaf0c` is used as the player index during the two overlay passes.
- `ui_transition_alpha` (`DAT_00487278`) is the frame alpha used by multiple render paths.

## HUD render (ui_render_hud / FUN_0041aed0)

The in-game HUD render is gated by `demo_mode_active` (`DAT_0048700d`) and is called from the main
UI pass (`hud_update_and_render`). It binds `ui_wicons` and uses `grim_set_sub_rect` for
weapon icons, along with health/score overlays.

## Terrain generation (terrain_generate / FUN_00417b80)

`terrain_generate` renders the terrain texture into a render target and selects
its base texture index from a per-level descriptor.

For the full pipeline (init, procedural stamping, FX decal baking, and final
screen draw), see [Terrain pipeline](terrain.md).

### Runtime evidence (2026-01-20)

`terrain_trace.jsonl` confirms the render path uses config-sized UVs over a
1024×1024 terrain texture:

- `u0 = -camera_offset_x / terrain_texture_width`
- `v0 = -camera_offset_y / terrain_texture_height`
- `u1 = u0 + (config_screen_width / terrain_texture_width)`
- `v1 = v0 + (config_screen_height / terrain_texture_height)`

Example capture (800×600 config, 1024×1024 terrain):
`u0=0.21875`, `u1=1.0`, `v0≈0.2228192`, `v1≈0.8087567` (deltas match
`800/1024` and `600/1024`). This matches the decompile and shows camera
clamping to the terrain edges.

The same trace confirms quest terrain indices:
`base/overlay/detail = (0,1,0)`, `(2,3,2)`, `(4,5,4)`, `(6,7,6)` for tiers 1–4,
matching the quest metadata and `terrain_ids_for` logic.

## UI overlays

`player_render_overlays` draws per-player indicators (aim reticles, shields,
weapon indicators). It is gated by `game_state_id` (`DAT_00487270`) values (not drawn in modal
states like `0x14/0x16`) and `ui_transition_alpha` (`DAT_00487278`) (transition alpha).

### Runtime evidence (2026-01-26)

`artifacts/frida/share/player_sprite_trace.jsonl` (`scripts/frida/player_sprite_trace.js`, summarized in `analysis/frida/player_sprite_trace_summary.json`) matches the decompile:

- Alive (`player_state_table.health > 0`): draws **two** sprite layers (UV frames `0..14` and `+0x10`) with a shadow/outline pass (scaled `~1.02/1.03` and offset) before the main pass; rotations come from `heading` vs `aim_heading`.
- Dead: draws a **single** sprite layer indexed by `ftol(death_timer)` (observed monotonic `32..52` then hold at `52` / `0x34` fallback), also with shadow+main passes.

### Player sprite UV tables (2026-01-26)

`player_render_overlays` uses two UV tables for the trooper sprite:

- Legs: `effect_uv8` (8×8 atlas grid, frames `0–14`, empty `15`)
- Torso: `DAT_00491090`, which is **`effect_uv8 + 16`** (frames `16–30`, empty `31`)

This table is not filled separately; it aliases into `effect_uv8`, which is populated by
`effect_uv_tables_init` (`FUN_0041fed0`), called during `game_startup_init_prelude` (`FUN_0042b090`).

Runtime trace (`artifacts/frida/share/player_sprite_trace.jsonl`) shows paired draw calls with indices
`(0,16) … (14,30)`, and the trooper atlas (`game/trooper.png`) has fully empty frames at 15 and 31,
matching the decompile and the observed render order.

### Recoil / muzzle-flash kick (2026-01-26)

Recoil is driven by `player_state.muzzle_flash_alpha`:

- Decay: `muzzle_flash_alpha = max(0, muzzle_flash_alpha - 2 * frame_dt)`
  (applied in both `player_update` and `player_fire_weapon`).

- On fire: `muzzle_flash_alpha += weapon_table[weapon_id].spread_heat`, then clamped
  (`<= 1.0` immediately, and `<= 0.8` at the end of `player_fire_weapon`).

TODO (runtime): confirm the **effective** decay rate and update order.
The decompile shows the same decay expression in both `player_update` and `player_fire_weapon`;
depending on call order and early returns, the value may decay once or twice per frame.

During `player_render_overlays`, the **torso quad** is offset by a recoil vector computed from aim heading:

- `dir = (cos(aim_heading + π/2), sin(aim_heading + π/2))`
- `offset = dir * (muzzle_flash_alpha * 12.0)`
- the torso quad is drawn at `(camera + pos - size/2) + offset`

The recoil pass uses the torso UV table (`DAT_00491090`) and rotates by `aim_heading`.
The shadow/highlight pass draws a slightly larger quad (`size * 1.03`) and shifts it by `(+1, +1)`.

See also:

- [Sprite atlas cutting](../atlas.md)
- [Creature pool struct](../creatures/struct.md)
- [Projectile struct](../structs/projectile.md)
- [Effects pools](../structs/effects.md)
