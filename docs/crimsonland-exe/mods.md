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

## Loading a mod interface

`mod_load_mod` (`0x0040e860`):

- Builds a path `mods\%s` and calls `LoadLibraryA`.
- Resolves `CMOD_GetMod` via `GetProcAddress`.
- Calls it and (on success) writes a context pointer at offset `+4` of the
  returned interface.
- Logs success/failure to the console.

## Open questions

- The exact layout of the `CMOD_GetInfo` struct is still unknown.
- The mod context pointer written at `+4` likely points to a global mod table
  (current mod name/metadata), but no other static xrefs yet.
