# Incoming Triage

This file consolidates the actionable bits from the old `incoming/*.md` scratch notes.

## Already Addressed (No Action)

- Console globals already mapped in `analysis/ghidra/maps/data_map.json`: `console_input_buf` (`0x0047e448`) and `console_input_cursor` (`0x0047ea54`).
- Console globals already mapped in `analysis/ghidra/maps/data_map.json`: `console_log_queue` and related fields.
- Grim2D vtable + config IDs already tracked in docs: `docs/grim2d/api.md`, `docs/grim2d/api-evidence.md`.
- Grim2D header already generated: `third_party/headers/grim2d.h` (from `analysis/ghidra/derived/grim2d_vtable_map.json`).
- Survival-mode behavior (native contract) already documented: `docs/crimsonland-exe/survival.md` + tests under `tests/`.
- Gameplay struct docs already exist: `docs/structs/*`, `docs/creatures/struct.md`, `docs/ui-elements.md`.
- Already in maps: `ui_draw_textured_quad` (`0x00417ae0`).
- Already in maps: `terrain_generate` (`0x00417b80`).
- Already in maps: `dsound_init` (`0x0043baf0`).
- Already in maps: `grim_set_config_var` (`0x10006580`).
- Already in maps: zlib/png symbols like `inflate`, `adler32`, `inflate_codes`, `huft_build`, `png_create_read_struct`.

## Backlog / Follow-Ups

Notes:

- Treat all names below as **proposed** until we can justify them with xrefs and/or runtime evidence.
- When promoting, match existing naming style (snake_case, subsystem prefixes like `ui_`, `console_`, `grim_`).

### crimsonland.exe: Proposed Function Renames (Need Evidence)

Currently present in `analysis/ghidra/maps/name_map.json` but still unnamed (`FUN_*`):

- `0x004010f0` `FUN_004010f0` → `Console_ExecCallbackList`
- `0x00401170` `FUN_00401170` → `Console_Create`
- `0x00401180` `FUN_00401180` → `Console_RegisterCleanup`
- `0x004016e0` `FUN_004016e0` → `Console_Destroy`
- `0x00401dd0` `FUN_00401dd0` → `Console_Render`
- `0x00402d50` `FUN_00402d50` → `UI_RenderLoading`
- `0x00403430` `FUN_00403430` → `UI_MouseInRect`
- `0x00406350` `FUN_00406350` → `Game_UpdateVictoryScreen`
- `0x00406af0` `FUN_00406af0` → `Game_UpdateGenericMenu`
- `0x004120b0` `FUN_004120b0` → `HighScore_ResetCurrent`
- `0x00412190` `FUN_00412190` → `Quest_Meta_Init`
- `0x00412360` `FUN_00412360` → `HighScore_InitSentinels`
- `0x00412940` `FUN_00412940` → `Bonus_ResetAvailability`
- `0x00417640` `FUN_00417640` → `Vec2_Sub`
- `0x0041e270` `FUN_0041e270` → `Vec2_Add`
- `0x0041fc80` `FUN_0041fc80` → `Player_ResetAll`
- `0x0042f080` `FUN_0042f080` → `Effect_SpawnBurst`
- `0x0042f270` `FUN_0042f270` → `Effect_SpawnShock`
- `0x0042f3f0` `FUN_0042f3f0` → `Effect_SpawnBloodRing`
- `0x0042f540` `FUN_0042f540` → `Effect_SpawnShockwave`
- `0x0043b810` `FUN_0043b810` → `BufferReader_Reset`
- `0x0043d9b0` `FUN_0043d9b0` → `UI_UpdateWidgetRect`
- `0x004443c0` `FUN_004443c0` → `UI_UpdateProfileMenu`
- `0x00445310` `FUN_00445310` → `Creature_IsNameTaken`
- `0x0044fb50` `FUN_0044fb50` → `UI_Layout_Calc`

Notable conflicts to resolve before promotion:

- Incoming suggested `0x00403430` as “mouse in rect”, but we already have `ui_mouse_inside_rect` at `0x004034a0`.
- Incoming suggested a rank/ordinal formatter at `0x00441270`, but we already have `format_ordinal` at `0x00406180`.

Missing from `analysis/ghidra/maps/name_map.json` entirely (add entries first, then decide renames):

- `0x00417660` → `Vec2_Length`
- `0x00417a90` → `UI_Element_Init`
- `0x004411c0` → `UI_DrawBox_Small`
- `0x00441220` → `UI_DrawBox_Large`
- `0x00441270` → `Format_RankString`
- `0x00446150` → `UI_GetElementIndex`

### grim.dll: Proposed Names + Missing Globals

Already named or otherwise redundant (no action):

- Vtable shape and most entry names exist (see `docs/grim2d/*` and `third_party/headers/grim2d.h`).
- zlib/png library symbols are already named in `analysis/ghidra/maps/name_map.json`.

Rename candidates in `analysis/ghidra/maps/name_map.json` (still `FUN_*`):

- `0x1001152a` `FUN_1001152a` → `grim_load_image_pnm`
- `0x100117ff` `FUN_100117ff` → `grim_load_image_png`
- `0x10011d95` `FUN_10011d95` → `grim_load_image_dds`
- `0x10012647` `FUN_10012647` → `grim_load_image_bmp`
- `0x10025163` `FUN_10025163` → `grim_png_read_IHDR`
- `0x10025359` `FUN_10025359` → `grim_png_read_PLTE`
- `0x1002587e` `FUN_1002587e` → `grim_png_read_chunk_generic`

Missing from `analysis/ghidra/maps/name_map.json` (add entries first, then decide renames):

- `0x10006030` → `grim_set_texture_stage_ops`
- `0x1001d220` → `grim_load_image_jpg`
- `0x100224c5` → `grim_init_mmx_sse_functions`

Global candidates missing from `analysis/ghidra/maps/data_map.json` (confirm in decompile first):

- `0x10053040` → `grim_vfs_pack_file`
- `0x10059e00` → `grim_d3d_pp`
- `0x10059e3c` → `grim_cwd`
- `0x1005a058` → `grim_key_repeat_timers`
- `0x1005a498` → `grim_d3d_caps`
- `0x1005b2b0` → `grim_config_hwnd`
- `0x1005b2b4` → `grim_d3d_devtype`
- `0x1005b2c0` → `grim_index_data_ptr`
- `0x1005bbd8` → `grim_main_loop_state`
- `0x1005ce18` → `grim_screen_width`
- `0x1005ce28` → `grim_screen_height`
- `0x1005d0c8` → `grim_windowed_mode`
- `0x1005d3e8` → `grim_adapter_index`
- `0x1005d3f8` → `grim_main_hwnd`
- `0x1005d3fc` → `grim_render_hwnd`
- `0x1005d804` → `grim_texture_count`

Tentative type notes worth encoding somewhere (optional; validate before trusting):

- `GrimTexture` (entry pointed to by `grim_texture_slots[handle]`): `{ char* name; IDirect3DTexture8* d3d_tex; bool is_loaded; int width; int height; IDirect3DSurface8* backup; }`
- `GrimVertex` (TLVertex; FVF `0x144`): `{ float x, y, z, rhw; DWORD color; float u, v; }`

### Python Port: Survival Integration (If Still The Goal)

This is rewrite work under `src/` and is separate from map promotion, but it was called out in the incoming notes.

- Remove hardcoded Survival RNG seed (`0xBEEF`) from `src/crimson/views/survival.py` and inject RNG/seed from `GameState`.
- Implement `CreatureFlags.SPLIT_ON_DEATH` behavior in `src/crimson/creatures/runtime.py`.
- Implement `CreatureFlags.RANGED_ATTACK_SHOCK` behavior in `src/crimson/creatures/runtime.py`.
- Implement `CreatureFlags.RANGED_ATTACK_VARIANT` behavior in `src/crimson/creatures/runtime.py`.
- Replace debug draw in Survival with existing render pipeline (ground, sprites/anim, projectiles, bonuses, fx).
- Wire gameplay SFX events (weapon fire/reload, bonus pickup, perk menu, ranged enemy fire).
- Add a headless Survival simulation harness/test for fast regression checks.

## Promotion Checklist (Maps)

When promoting any of the rename/global candidates above:

- Update `analysis/ghidra/maps/name_map.json` and/or `analysis/ghidra/maps/data_map.json`.
- Regenerate derived exports via `just ghidra-exe` (or `just ghidra-sync` when using WSL + Windows).
- Add/adjust docs under `docs/` when behavior becomes confidently understood.
