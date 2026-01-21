---
tags:
  - status-draft
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
| `0x44` | `api_version` (`u32`) | Mod API/version marker | Both mods write `3`; the exe seeds `DAT_00481ccc = 3` during init. |

## Loading a mod interface

`mod_load_mod` (`0x0040e860`):

- Builds a path `mods\%s` and calls `LoadLibraryA`.
- Resolves `CMOD_GetMod` via `GetProcAddress`.
- Calls it and (on success) writes a context pointer at offset `+4` of the
  returned interface.
- Logs success/failure to the console.

### Mod interface object (CMOD_GetMod)

The mod interface object is a 0x408-byte allocation with a vtable pointer at
offset `0x00`. The exe drives the vtable and pokes a few flags directly.

| Offset | Field | Meaning | Evidence |
| --- | --- | --- | --- |
| `0x00` | `vtable` | Function table (3 slots used) | Exe calls `(*vtable)[0]`, `(*vtable)[1]`, `(*vtable)[2](frame_dt_ms)`. |
| `0x04` | `context` | Mod context pointer | Exe writes `&DAT_00481a80` at `+4` after `CMOD_GetMod`. |
| `0x08` | `flags` | Cursor/visibility flags (low byte) | Exe checks `(char)plugin_interface_ptr[2]` to decide whether to draw the cursor. |
| `0x24` | `request_exit` | Exit/request flag byte | Exe sets byte `+0x24` when leaving or pausing the plugin flow. |

## Open questions

- Meaning of `api_version` (always `3` in bundled mods) and the `flags` word at `+0x08`.
- The rest of the 0x408-byte interface object and any additional vtable slots.
- The mod context pointer written at `+4` likely points to a global mod table
  (current mod name/metadata), but no other static xrefs yet.
