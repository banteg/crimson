# Rendering pipeline

**Status:** Draft

This page summarizes the primary render paths in `crimsonland.exe`.

## Render dispatcher (FUN_00406af0)

- If `render_pass_mode` (`DAT_00487240`) == `0` and `game_state_id` (`DAT_00487270`) != `5`, it draws terrain only via
  `FUN_004188a0`.
- Otherwise it runs the full gameplay render pass `FUN_00405960`.
- After either branch it applies a fullscreen fade (`DAT_00487264`), runs
  `ui_elements_update_and_render`, calls `FUN_00403550` (perk prompt), and
  renders the UI cursor.

## Gameplay render pass (FUN_00405960)

Order of major passes:

1) `fx_queue_render` (`FUN_00427920`)
2) `FUN_004188a0` (terrain/backbuffer blit)
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

## HUD render (FUN_0041ca90 / FUN_0041aed0)

The in-game HUD render is gated by `demo_mode_active` (`DAT_0048700d`) and is called from the main
UI pass (`FUN_0041ca90`). It binds `ui_wicons` and uses `grim_set_sub_rect` for
weapon icons, along with health/score overlays.

## Terrain generation (FUN_00417b80)

`terrain_generate` renders the terrain texture into a render target and selects
its base texture index from a per-level descriptor.

## UI overlays

`player_render_overlays` draws per-player indicators (aim reticles, shields,
weapon indicators). It is gated by `game_state_id` (`DAT_00487270`) values (not drawn in modal
states like `0x14/0x16`) and `ui_transition_alpha` (`DAT_00487278`) (transition alpha).

See also:

- [Sprite atlas cutting](../atlas.md)
- [Creature struct](../creature-struct.md)
- [Projectile struct](../projectile-struct.md)
- [Effects pools](../effects-struct.md)
