---
tags:
  - status-analysis
---

# Mods (CMOD plugins)

Crimsonland has a lightweight plugin system that loads DLLs from the `mods\` folder
and expects two exports: `CMOD_GetInfo` and `CMOD_GetMod`.

## Discovery

- The game checks for any mod DLLs via `mods_any_available` (`0x0040e940`).
- It searches the filesystem with `mods\*.dll` (`FindFirstFileA` / `FindNextFileA`).
- In `game_state_set` (`0x004461c0`), this boolean gates whether the mods entry
  is enabled in the main menu flow.

## Loading a mod info block

`mod_load_info` (`0x0040e700`):

- Builds a path `mods\%s` and calls `LoadLibraryA`.
- Resolves `CMOD_GetInfo` via `GetProcAddress`.
- Calls it and copies the returned struct into `DAT_00481c88` (0x12 dwords).
- Logs either the info or an error string to the console.

### Mod info layout (CMOD_GetInfo)

Both bundled mods (`cl_nullmod.dll`, `cl_crimsonroks.dll`) return a 0x48-byte
struct with two fixed-size strings and two scalar fields. The executable also
seeds the tail values (`1.0f`, `3`) before copying.

| Offset | Field | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x00` | `name[0x20]` | Mod display name (NUL-terminated) | Mod DLLs zero 0x20 bytes then copy `"Null Example Mod"` / `"CrimsonRoks"` into the base. |
| `0x20` | `author[0x20]` | Author string (NUL-terminated) | Mod DLLs copy `"temper / 10tons"` into the second 0x20 block. |
| `0x40` | `version` (`float`) | Mod version | `cl_nullmod` writes `1.0f`; `cl_crimsonroks` writes `0.2f`. |
| `0x44` | `usesApiVersion` (`u32`) | Mod API/version marker | Both mods write `3` (`CL_API_VERSION` in `cl_mod_sdk_v1/ClMod.h`); the exe seeds `DAT_00481ccc = 3` during init. |

## Loading a mod interface

`mod_load_mod` (`0x0040e860`):

- Builds a path `mods\%s` and calls `LoadLibraryA`.
- Resolves `CMOD_GetMod` via `GetProcAddress`.
- Calls it and (on success) writes a context pointer at offset `+4` of the
  returned interface.

- Logs success/failure to the console.

### Mod interface object (CMOD_GetMod)

The mod interface object is a 0x408-byte allocation with a vtable pointer at
offset `0x00`. This matches `modExport_t` from `cl_mod_sdk_v1/ClMod.h` (C++
interface + a 0x400-byte parms block).

| Offset | Field | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x00` | `vtable` | Function table (3 slots used) | Exe calls `(*vtable)[0]`, `(*vtable)[1]`, `(*vtable)[2](frame_dt_ms)`. |
| `0x04` | `cl` | Mod API context pointer | Exe writes `&DAT_00481a80` at `+4` after `CMOD_GetMod`. |
| `0x08` | `parms.drawMouseCursor` | Draw the standard cursor | Mods set this to `1`; exe checks `(char)plugin_interface_ptr[2]` to decide whether to draw the cursor. |
| `0x09` | `parms.onPause` | Pause hint from the engine | `cl_crimsonroks` gates updates on `parms.onPause`; exe sets `*(plugin_interface_ptr + 9) = 1` when pausing. |
| `0x24` | `parms.request_exit` | Exit/request flag byte | Exe sets byte `+0x24` when leaving or pausing the plugin flow (part of the reserved parms block). |

### Mod interface vtable (3 slots)

The bundled mods use a 3-entry vtable. The update slot returns a byte that
drives whether the exe keeps the mod active.

| Slot | Meaning | Evidence |
| --- | --- | --- |
| `0` | `Init()` | Both mods cache the context pointer and set `parms.drawMouseCursor` (byte `+0x08`) to `1`. |
| `1` | `Shutdown()` | Both mods call internal cleanup helpers and `delete this`. |
| `2` | `Frame(frame_dt_ms)` | Returns `0` to exit (exe closes the plugin). Used to poll keys and issue `"game_pause"`. |

### Mod API context (DAT_00481a80)

The context pointer passed at `+0x04` is treated as a vtable-based API from
within the mod DLLs. The layout matches `clAPI_t` in `cl_mod_sdk_v1/ClMod.h`
(API v3), and the vtable pointer is set to `0x0046f3e4` during init.

| Vtable offset | SDK name | Wrapper (crimsonland.exe) | Notes |
| --- | --- | --- | --- |
| `0x00` | `CORE_Printf` | `mod_api_core_printf` (`0x0040e000`) | Uses `OutputDebugStringA`. |
| `0x04` | `CORE_GetVar` | `mod_api_core_get_var` (`0x0040e040`) | Returns a 3-pointer `var_t` view (`id`, `stringValue`, `floatValue`). |
| `0x08` | `CORE_DelVar` | `mod_api_core_del_var` (`0x0040e080`) | Unregisters a cvar. |
| `0x0c` | `CORE_Execute` | `mod_api_core_execute` (`0x0040e0a0`) | Executes a console line. |
| `0x10` | `CORE_AddCommand` | `mod_api_core_add_command` (`0x0040e0c0`) | Registers a console command. |
| `0x14` | `CORE_DelCommand` | `mod_api_core_del_command` (`0x0040e0e0`) | Unregisters a command. |
| `0x18` | `CORE_GetExtension` | `mod_api_core_get_extension` (`0x0040e100`) | Handles `"grimgfx"`, `"grimsfx"`, `"IDirect3D8"`. |
| `0x1c` | `GFX_Clear` | `mod_api_gfx_clear` (`0x0040e1f0`) | Bridges to `grim_clear_color`. |
| `0x20` | `GFX_GetStringWidth` | `mod_api_gfx_get_string_width` (`0x0040e220`) | Bridges to `grim_measure_text_width`. |
| `0x24` | `GFX_Printf` | `mod_api_gfx_printf` (`0x0040e240`) | Preformats into a global buffer, then draws text. |
| `0x28` | `GFX_LoadTexture` | `mod_api_gfx_load_texture` (`0x0040e280`) | Loads `mods\\%s` via `texture_get_or_load("CLM_%s", ...)`. |
| `0x2c` | `GFX_FreeTexture` | `mod_api_gfx_free_texture` (`0x0040e2e0`) | Bridges to `grim_destroy_texture`. |
| `0x30` | `GFX_SetTexture` | `mod_api_gfx_set_texture` (`0x0040e300`) | Bridges to `grim_bind_texture(handle, 0)`. |
| `0x34` | `GFX_SetTextureFilter` | `mod_api_gfx_set_texture_filter` (`0x0040e380`) | Bridges to `grim_set_config_var(21, filter)`. |
| `0x38` | `GFX_SetBlendMode` | `mod_api_gfx_set_blend_mode` (`0x0040e3a0`) | Bridges to `grim_set_config_var(19, src)` / `(20, dst)`. |
| `0x3c` | `GFX_SetColor` | `mod_api_gfx_set_color` (`0x0040e320`) | Bridges to `grim_set_color`. |
| `0x40` | `GFX_SetSubset` | `mod_api_gfx_set_subset` (`0x0040e350`) | Bridges to `grim_set_uv`. |
| `0x44` | `GFX_Begin` | `mod_api_gfx_begin` (`0x0040e3e0`) | Bridges to `grim_begin_batch`. |
| `0x48` | `GFX_End` | `mod_api_gfx_end` (`0x0040e400`) | Bridges to `grim_end_batch`. |
| `0x4c` | `GFX_Quad` | `mod_api_gfx_quad` (`0x0040e420`) | Bridges to `grim_draw_quad`. |
| `0x50` | `GFX_QuadRot` | `mod_api_gfx_quad_rot` (`0x0040e470`) | Sets rotation then draws a quad. |
| `0x54` | `GFX_DrawQuads` | `mod_api_gfx_draw_quads` (`0x0040e4c0`) | Submits vertex data (offset 0,0). |
| `0x58` | `SFX_LoadSample` | `mod_api_sfx_load_sample` (`0x0040e530`) | Loads `mods\\%s` via `sfx_load_sample`. |
| `0x5c` | `SFX_FreeSample` | `mod_api_sfx_free_sample` (`0x0040e560`) | Releases a sample. |
| `0x60` | `SFX_PlaySample` | `mod_api_sfx_play_sample` (`0x0040e570`) | `pan` is scaled by `512.0`. |
| `0x64` | `SFX_LoadTune` | `mod_api_sfx_load_tune` (`0x0040e5b0`) | Loads `mods\\%s` via `music_load_track`. |
| `0x68` | `SFX_FreeTune` | `mod_api_sfx_free_tune` (`0x0040e5e0`) | Releases a track handle. |
| `0x6c` | `SFX_PlayTune` | `mod_api_sfx_play_tune` (`0x0040e5f0`) | Wrapper name suggests SFX; likely “exclusive” tune play. |
| `0x70` | `SFX_StopTune` | `mod_api_sfx_stop_tune` (`0x0040e600`) | Wrapper name suggests SFX; likely tune stop/mute. |
| `0x74` | `INP_KeyDown` | `mod_api_inp_key_down` (`0x0040e660`) | Uses `grim_is_key_active` (key `1` forced false). |
| `0x78` | `INP_GetAnalog` | `mod_api_inp_get_analog` (`0x0040e620`) | Special-cases `DIKA_MOUSEXSTAT`/`DIKA_MOUSEYSTAT` (355/356). |
| `0x7c` | `INP_GetPressedChar` | `mod_api_inp_get_pressed_char` (`0x0040e610`) | Bridges to `grim_get_key_char`. |
| `0x80` | `INP_GetKeyName` | `mod_api_inp_get_key_name` (`0x0040e680`) | Bridges to `input_key_name`. |
| `0x84` | `CL_EnterMenu` | `mod_api_cl_enter_menu` (`0x0040e690`) | Only handles `"game_pause"`. |

## Open questions

- Remaining semantics of the reserved `parms` bytes beyond `drawMouseCursor`, `onPause`, and the observed `request_exit` flag.
- Better naming for the tune wrappers (`SFX_PlayTune` / `SFX_StopTune`) if they differ from the core SFX system behavior.
