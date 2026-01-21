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

### Mod interface vtable (3 slots)

The bundled mods use a 3-entry vtable. The update slot returns a byte that
drives whether the exe keeps the mod active.

| Slot | Meaning | Evidence |
| --- | --- | --- |
| `0` | `on_enter` / init | Both mods cache the context pointer and set `flags` byte `+0x08` to `1`. |
| `1` | `on_exit` / shutdown | Both mods call internal cleanup helpers and return. |
| `2` | `on_update(frame_dt_ms)` | Returns `0` to exit (exe closes the plugin). Used to poll keys and issue `"game_pause"`. |

### Mod API context (DAT_00481a80)

The context pointer passed at `+0x04` is treated as a vtable-based API from
within the mod DLLs. Known call sites:

| Vtable offset | Signature (inferred) | Usage |
| --- | --- | --- |
| `0x1c` | `fn(self, float a, float b, float c, float d)` | `cl_nullmod` calls with zeros (likely a clear/color or render-state helper). |
| `0x74` | `key_query(self, int key)` | Both mods call with `0x3b`/`0x3c` (F1/F2) and branch on `al`. |
| `0x84` | `exec_command(self, const char *cmd)` | Called with `"game_pause"` when the F1 path triggers. |

## Open questions

- Meaning of `api_version` (always `3` in bundled mods) and the `flags` word at `+0x08`.
- The rest of the 0x408-byte interface object and any additional vtable slots.
- Precise semantics of the mod API vtable slots (0x1c/0x74/0x84) beyond the observed usage.
