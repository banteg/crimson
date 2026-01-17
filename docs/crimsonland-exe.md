# Crimsonland.exe overview

**Status:** Draft

This page captures the high-level frame flow for the classic Windows build
(v1.9.93) from `source/decompiled/crimsonland.exe_decompiled.c`.
See [Entrypoint trace](entrypoint.md) for the boot sequence.

## Render dispatcher (FUN_00406af0)

- When `DAT_00487240 == 0` and `DAT_00487270 != 5`, it draws terrain only via
  `FUN_004188a0`.
- Otherwise it runs the full gameplay render pass `FUN_00405960`.
- After either branch it applies a fullscreen fade and calls `FUN_0041a530`,
  `FUN_00403550`, and `ui_cursor_render`.

## Gameplay render pass (FUN_00405960)

Order of major passes:

1) `fx_queue_render` (`FUN_00427920`)
2) `FUN_004188a0` (terrain/backbuffer blit)
3) `player_render_overlays` (`FUN_00428390`) for players with `DAT_004908d4 <= 0`
4) `creature_render_all` (`FUN_00419680`)
5) `player_render_overlays` for players with `DAT_004908d4 > 0`
6) `projectile_render` (`FUN_00422c70`)
7) `bonus_render`
8) `grim_draw_fullscreen_color` fade when `DAT_00487264 > 0`

Notes:

- `DAT_004aaf0c` is used as the player index during the two overlay passes.
- `DAT_00487278` is the frame alpha used by multiple render paths.

## HUD render (FUN_0041aed0)

The in-game HUD render is gated by `DAT_0048700d` and is called from the main UI
pass (`FUN_0041ca90`). It binds `ui_wicons` and uses `grim_set_sub_rect` for
weapon icons, along with health/score overlays.

## Player update (FUN_004136b0)

`player_update` runs once per player index during the gameplay update loop
(`DAT_00487270 == 9`). It handles per-player movement, weapon firing, and
status timers, and it spawns effects or projectiles for the current player.

## Quest results screen (FUN_00410d20)

`quest_results_screen_update` renders the post‑mission summary:

- Final time and “Unpicked Perk Bonus” lines.
- High score entry when appropriate.
- Buttons: Play Next / Play Again / High scores / Main Menu.
- Special case for the final quest: “Show End Note”.

## Demo purchase screen (FUN_0040b740)

`demo_purchase_screen_update` is the full‑screen upsell flow. It renders the
feature list, shows the logo/mockup, and opens the purchase URL when the user
clicks “Purchase”.

## Demo trial overlay (FUN_004047c0)

`demo_trial_overlay_render` draws the demo warning panel with the remaining
trial time and “upgrade to full version” copy.

## Terrain generation (FUN_00417b80)

`terrain_generate` renders the terrain texture into a render target and selects
the base texture index from a per‑level descriptor.

## UI elements (FUN_00446c40)

`ui_element_render` updates focus/click handling and renders a UI element’s
quads, colors, and textures. See [UI elements](ui-elements.md) for the struct
notes.

## Menu/UI update helpers

- `FUN_0041a530` runs every frame in most UI/gameplay loops; it advances the
  global transition timer (`DAT_00487248`) and applies state changes when the
  timer wraps.
- `FUN_00405be0` is one of the menu UI loops (uses `ui_button_update` and perk
  tables) and still calls `FUN_00405960` + `FUN_0041a530` before button handling.
