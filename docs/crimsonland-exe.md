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
  `FUN_00403550`, and `FUN_0041a040`.

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

## Menu/UI update helpers

- `FUN_0041a530` runs every frame in most UI/gameplay loops; it advances the
  global transition timer (`DAT_00487248`) and applies state changes when the
  timer wraps.
- `FUN_00405be0` is one of the menu UI loops (uses `ui_button_update` and perk
  tables) and still calls `FUN_00405960` + `FUN_0041a530` before button handling.
